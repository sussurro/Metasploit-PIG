#!/usr/bin/ruby
require 'rubygems'
require 'msfrpc-client'
require 'pp'


# Use the RPC option parser to handle standard flags
opts = {
	:host => '127.0.0.1',
	:port => 55552,
	:uri =>  '/api/',
	:ssl => false,
}

# Create the RPC client with our parsed options
rpc = Msf::RPC::Client.new(opts)

rpc.login('msf','abc123')

creds = rpc.call('db.creds',{})
v1_hashes = []
v2_hashes = []

creds['creds'].each do |c| 
	next unless c['type'].include? "smb_"
	if c['type'].include? "smb_netv1"
		v1_hashes << "#{c['user']}::#{c['pass']}" 
	else
		parts = c['pass'].split(":")
			
		v2_hashes << "#{c['user']}::#{parts[0]}:#{parts[3]}:#{parts[2][0,32]}:#{parts[2][32..-1]}" 
	end
end

file = File.open("netntlm.john","w")
v1_hashes.each do |h|
	file.write("#{h}\n")
end
file.close
file = File.open("netntlmv2.john","w")
v2_hashes.each do |h|
	file.write("#{h}\n")
end
file.close
