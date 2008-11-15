# Invaluable resources:
#  http://msdn2.microsoft.com/en-us/magazine/bb985043.aspx
#  http://doc.ddart.net/msdn/header/include/sspi.h.html

require 'mongrel'
require 'mongrel_ntlm/server_ntlm'

# Mongrel sends a Connection: Close to close off connections after each request
# but the NTLM handshake involves three legs on a persistent connection
module Mongrel
  module Const
    NTLM_STATUS_FORMAT = "HTTP/1.1 %d %s\r\n".freeze
    REMOTE_USER = 'REMOTE_USER'.freeze
    HTTP_AUTHORIZATION = 'HTTP_AUTHORIZATION'.freeze
    HTTP_X_MONGREL_PID = 'HTTP_X_MONGREL_PID'.freeze
  end

  # Custom methods for supporting NTLM authentication requests
  module NtlmHttpRequest
    def ntlm_token
      auth = params[Const::HTTP_AUTHORIZATION]
      return nil unless auth && auth.match(/\ANTLM (.*)\Z/)
      Base64.decode64($1.strip)
    end

    # Create a new HttpRequest object from the same socket and steal its body.
    # Mostly just the main loop of mongrel.
    def ntlm_refresh
      parser = HttpParser.new
      new_params = HttpParams.new
      new_request = nil
      data = @socket.readpartial(Const::CHUNK_SIZE)
      nparsed = 0

      while nparsed < data.length
        nparsed = parser.execute(params, data, nparsed)
        if parser.finished?
          new_params[Const::REQUEST_PATH] ||= @params[Const::REQUEST_PATH]
          raise "No REQUEST PATH" unless new_params[Const::REQUEST_PATH]
          
          new_params[Const::PATH_INFO] = @params[Const::PATH_INFO]
          new_params[Const::SCRIPT_NAME] = @params[Const::SCRIPT_NAME]
          new_params[Const::REMOTE_ADDR] = @params[Const::REMOTE_ADDR]
          
          new_request = HttpRequest.new(params, @socket, [])
          break
        else
          # Parser is not done, queue up more data to read and continue parsing
          chunk = @socket.readpartial(Const::CHUNK_SIZE)
          break if !chunk or chunk.length == 0  # read failed, stop processing

          data << chunk
          if data.length >= Const::MAX_HEADER
            raise HttpParserError.new("HEADER is longer than allowed, aborting client early.")
          end
        end
      end
      
      @params = params
      @body.close
      @body = new_request.body
    rescue HttpParserError => e
      STDERR.puts "#{Time.now}: HTTP parse error, malformed request (#{params[Const::HTTP_X_FORWARDED_FOR] || client.peeraddr.last}): #{e.inspect}"
      STDERR.puts "#{Time.now}: REQUEST DATA: #{data.inspect}\n---\nPARAMS: #{params.inspect}\n---\n"
    end
  end

  # Custom methods for supporting NTLM authentication responses
  module NtlmHttpResponse
    def send_ntlm_status(content_length=@body.length)
      unless @status_sent
        @header['Content-Length'] = content_length if content_length and @status != 304
        write(Const::NTLM_STATUS_FORMAT % [@status, @reason || HTTP_STATUS_CODES[@status]])
        @status_sent = true
      end
    end

    def ntlm_finished
      send_ntlm_status
      send_header
    end

    def ntlm_reset
      @header.out.truncate(0)
      @body.close
      @body = StringIO.new
      @status_sent = @header_sent = @body_sent = false
    end
  end
end

# Intercepts requests for the login page and injects the username in a request header
# if the user successfully completes NTLM authentication.
#
# Passes through to the regular login page if anything goes wrong.
class NtlmHandler < Mongrel::HttpHandler
  def process(request, response)
    # clear headers of data that we did not set
    request.params.delete('REMOTE_USER')
    request.params.delete('HTTP_X_MONGREL_PID')
    
    # add NTLM capabilities to the request and response
    request.extend(Mongrel::NtlmHttpRequest)
    response.extend(Mongrel::NtlmHttpResponse)
    
    return process_no_auth(request, response) if request.ntlm_token.nil?
    
    ntlm = Win32::SSPI::ServerNtlm.new
    ntlm.acquire_credentials_handle
    
    process_type1_auth(ntlm, request, response)
    request.ntlm_refresh
    response.ntlm_reset
    
    process_type3_auth(ntlm, request, response)
    
    request.params[Mongrel::Const::REMOTE_USER] = ntlm.get_username_from_context
    request.params[Mongrel::Const::HTTP_X_MONGREL_PID] = Process.pid.to_s
  rescue
    STDERR.puts "#{Time.now}: NTLM authentication error: #{$!.inspect}"
    response.ntlm_reset
  ensure
    ntlm.cleanup unless ntlm.nil?
  end

  protected
  # No NTLM header sent, ask for one and close the connection.
  def process_no_auth(request, response)
    response.start(401, true) do |head,out|
      head['WWW-Authenticate'] = 'NTLM'
    end
  end
  
  # First leg of NTLM authentication is to process the Type 1 NTLM Message from the client.
  def process_type1_auth(ntlm, request, response)
    t1 = request.ntlm_token
    t2 = ntlm.accept_security_context(t1)

    response.start(401) do |head,out|
      head['WWW-Authenticate'] = "NTLM #{t2}"
    end
    
    response.ntlm_finished
  end
  
  # Third leg of NTLM authentication is to process the Type 3 NTLM Message from the client.
  def process_type3_auth(ntlm, request, response)
    t3 = request.ntlm_token
    t2 = ntlm.accept_security_context(t3)
    
    # try to give rails as pristine a response object as possible
    response.ntlm_reset
  end
end