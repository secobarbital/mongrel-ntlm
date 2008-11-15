# The rubysspi gem provides a ruby interface to the SSPI functions in Windows
# but it is mostly concerned with the client side of SSPI, to get through corporate
# firewalls with NTLM.
#
# We extend it here to also support the server side of SSPI to support our mongrel handler

require 'win32/sspi'

module Win32
  module SSPI
    SECPKG_ATTR_NAMES = 0x00000001
    ASC_REQ_DELEGATE = 0x00000001

    module API
      AcceptSecurityContext = Win32API.new('secur32', 'AcceptSecurityContext', 'pppLLpppp', 'L')
      FreeContextBuffer = Win32API.new('secur32', 'FreeContextBuffer', 'P', 'L')
      QueryContextAttributes = Win32API.new('secur32', 'QueryContextAttributes', 'pLp', 'L')
      Strncpy = Win32API.new('msvcrt', 'strncpy', 'PLL', 'L')
    end
    
    class SecPkgCredentials_Names
      BUF_SZ = 512
      
      def initialize
        @buffer = "\0" * BUF_SZ
      end
      
      def to_s
        API::Strncpy.call(@buffer, @struct.unpack('L')[0], BUF_SZ-1) if @buffer.rstrip.empty?
        @buffer.rstrip
      end
      
      def to_p
        @struct ||= [@buffer].pack('p')
      end
      
      def cleanup
        API::FreeContextBuffer.call(self.to_p)
      end
    end
  end
end
