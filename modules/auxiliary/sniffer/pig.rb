require 'msf/core'
require 'pp'
require 'ruby-prof'


class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report
	include Msf::Exploit::Capture
	

	def initialize
		super(
			'Name'				=> 'Passive Information Gathering',
			'Version'           => '$Revision: $',
			'Id'           => '$Id: $',
			'Description'       => 'This module sniffs packets and gathers information',
			'Author'			=> 'sussurro@happypacket.net',
			'License'			=> MSF_LICENSE,
			'Actions'			=>
				[
					[ 'Sniffer' ],
					[ 'List'    ]
				],
			'PassiveActions' =>
				[
					'Sniffer'
				],
			'DefaultAction'	 => 'Sniffer'
		)

		register_options([
			OptString.new('PROTOCOLS',	[true,	'A comma-delimited list of protocols to sniff or "all".', "all"]),
		], self.class)

		register_advanced_options([
			OptPath.new('ProtocolBase', [true,	'The base directory containing the protocol decoders',
				File.join(Msf::Config.install_root, "data", "exploits", "pig")
			]),
		], self.class)
		deregister_options('RHOST')
	end


	def load_protocols
		base = datastore['ProtocolBase']
		if (not File.directory?(base))
			raise RuntimeError,"The ProtocolBase parameter is set to an invalid directory"
		end

		@protos = {}
		decoders = Dir.new(base).entries.grep(/\.rb$/).sort
		decoders.each do |n|
			f = File.join(base, n)
			m = ::Module.new
			begin
				m.module_eval(File.read(f, File.size(f)))
				m.constants.grep(/^Pig(.*)/) do
					proto = $1
					klass = m.const_get("Pig#{proto}")
					@protos[proto.downcase] = klass.new(framework, self)

					print_status("Loaded protocol #{proto} from #{f}...")
				end
			rescue ::Exception => e
				print_error("Decoder #{n} failed to load: #{e.class} #{e} #{e.backtrace}")
			end
		end
	end

	def run
		# Load all of our existing protocols
		load_protocols

		if(action.name == 'List')
			print_status("Protocols: #{@protos.keys.sort.join(', ')}")
			return
		end

		# Remove protocols not explicitly allowed
		if(datastore['PROTOCOLS'] != 'all')
			allowed = datastore['PROTOCOLS'].split(',').map{|x| x.strip.downcase}
			newlist = {}
			@protos.each_key { |k| newlist[k] = @protos[k] if allowed.include?(k) }
			@protos = newlist
		end

		print_status("Sniffing traffic.....")
		#RubyProf.start
		open_pcap
		i = 0
		each_packet do |pkt|
			packet = PacketFu::Packet.parse(pkt)
			@protos.each_key do |k|
				next if not @protos[k].can_parse(packet)
				@protos[k].parse(packet)
			end
		end
		close_pcap
		print_status("Done")
		#result = RubyProf.stop
		#printer = RubyProf::CallTreePrinter.new(result)
		#myfile = open("/tmp/ttqq","w+")
  		#printer.print(myfile, {:min_percent => '20'})
		#print_status("Finished sniffing")
	end
end

# End module class

class PigParser

	attr_accessor :rules, :framework , :module

	def initialize(framework,mod)
		self.framework = framework
		self.module = mod
		self.rules = {}
		register_rules()
	end

	def register_rules
		self.rules = {}
	end

	def parse(pkt)
		nil
	end

	def print_status(msg)
		self.module.print_status(msg)
	end

	def print_error(msg)
		self.module.print_error(msg)
	end

	def report_auth_info(*s)
		self.module.report_auth_info(*s)
	end

	def report_service(*s)
		self.module.report_service(*s)
	end

	def report_host(*s)
		self.module.report_host(*s)
	end

	def report_note(*s)
		self.module.report_note(*s)
	end
	def store_loot(*s)
		self.module.store_loot(*s)
	end

end

