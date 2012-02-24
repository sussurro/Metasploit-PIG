require 'pp'
module PacketFu

	# SNAPHeader is incomplete.  I just have a basic understanding of 
	# how it works.  As such, I've applied the minimum necessary till a 
	# networking ninja can make this work.
	#
	# ==== Header Definition
	#
	#   Int32   :snap_oui                         # OUI 
	#   Int16   :snap_type                        # Type
	#   String  :body
	class SNAPHeader < Struct.new(:snap_oui, :snap_type, :body)

		include StructFu

		def initialize(args={})
			super(
				Int32.new(args[:snap_oui]),
				Int16.new(args[:snap_type]),
				StructFu::String.new.read(args[:body])
			)
		end

		# Returns the object in string form.
		def to_s
			self.to_a.map {|x| x.to_s}.join
		end

		# Reads a string to populate the object.
		def read(str)
			force_binary(str)
			return self if str.nil?
			self[:snap_oui].read("\x00" + str[3,3])
			self[:snap_type].read(str[6,2])
			self[:body].read(str[8,str.size])
			self
		end

		# Setter for the oui.
		def snap_oui=(i); typecast i; end
		# Getter for the oui.
		def snap_oui; self[:snap_oui].to_i; end
		# Setter for the type.
		def snap_type=(i); typecast i; end
		# Getter for the type.
		def snap_type; self[:snap_type].to_i; end
		
	end

	# SNAPPacket is used to construct SNAP Packets. They contain an EthHeader and a SNAPHeader.
	#
	# == Example
	#
	#  snap_pkt.new
	#  snap_pkt.snap_oui = 12
	#  snap_pkt.snap_type = 8192
	#  snap_pkt.body = (CDP DATA)
	#
	# == Parameters
	#
	#  :eth
	#   A pre-generated EthHeader object.
	class SNAPPacket < Packet

		attr_accessor :eth_header, :snap_header

		def self.can_parse?(str)
			return false unless EthPacket.can_parse? str
			return false unless str[14,3] == "\xaa\xaa\x03"
			return true
		end

		def read(str=nil, args={})
			raise "Cannot parse `#{str}'" unless self.class.can_parse?(str)
			@eth_header.read(str)
			@snap_header.read(str[14,str.size])
			@eth_header.body = @snap_header
			super(args)
			self
		end

		def initialize(args={})
			@eth_header = EthHeader.new(args).read(args[:eth])
			@snap_header = SNAPHeader.new(args).read(args[:snap])

			@eth_header.body = @snap_header

			@headers = [@eth_header, @snap_header]
			super
		end

		# Peek provides summary data on packet contents.
		def peek_format
			peek_data = ["SNAP "] # I is taken by IP
			peek_data << "%-5d" % self.to_s.size
			peek_data << "%04x" % self.snap_oui.to_i
			type = case self.snap_type.to_i
						 when 8192
							 "CDP"
						 else
							 "%04x" % [self.snap_type]
						 end
			peek_data << "%-21s" % "#{type}"
			peek_data.join
		end

	end

end
