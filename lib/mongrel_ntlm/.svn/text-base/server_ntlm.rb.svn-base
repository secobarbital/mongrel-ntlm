# Encapsulate all the server-side NTLM logic and data structures in a class.
# Using one instance of this class per connection makes it easy to clean up.

require 'mongrel_ntlm/rubysspi_extensions'

module Win32
  module SSPI
    class ServerNtlm
      WORD_SZ = [0].pack('L').size
      
      def acquire_credentials_handle
        @credentials = CredHandle.new
        
        result = SSPIResult.new(API::AcquireCredentialsHandle.call(
          nil,
          "NTLM",
          SECPKG_CRED_INBOUND,
          nil,
          nil,
          nil,
          nil,
          @credentials.to_p,
          TimeStamp.new.to_p
        ))
        raise "AcquireCredentialsHandle Error: #{result}" unless result.ok?
      end
      
      def accept_security_context(token)
        incoming = SecurityBuffer.new(token)
        outgoing = SecurityBuffer.new
        
        current_context = @context.nil? ? nil : @context.to_p
        @context ||= CtxtHandle.new
        @contextAttributes = "\0" * WORD_SZ
        
        result = SSPIResult.new(API::AcceptSecurityContext.call(
          @credentials.to_p,
          current_context,
          incoming.to_p,
          ASC_REQ_DELEGATE,
          SECURITY_NETWORK_DREP,
          @context.to_p,
          outgoing.to_p,
          @contextAttributes,
          TimeStamp.new.to_p
        ))
        raise "AcceptSecurityContext Error: #{result}" unless result.ok?
        
        Base64.encode64(outgoing.token).delete("\n")
      end
      
      def get_username_from_context
        return @username unless @username.nil?
        return nil if @context.nil?
        
        names = SecPkgCredentials_Names.new
        result = SSPIResult.new(API::QueryContextAttributes.call(
          @context.to_p,
          SECPKG_ATTR_NAMES,
          names.to_p
        ))
        @username = names.to_s if result.ok?
      ensure
        names.cleanup
      end
      
      def cleanup
        API::FreeCredentialsHandle.call(@credentials.to_p) unless @credentials.nil?
        API::DeleteSecurityContext.call(@context.to_p) unless @context.nil?
        @credentials = @context = @contextAttributes = nil
      end
    end
  end
end