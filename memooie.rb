require 'rack/session/cookie'

#
# @author Alejandro El Infomático
#
# based on the original work from https://github.com/rack/rack/blob/master/lib/rack/session/cookie.rb
#

module Rack
  module Session

    # Use Rack::Session::Cookie to save only session-related info in the cookie
    # and use memory to save all the other data.
    #
    # The data saved to cookie is: session_id and keys containing padrino
    #
    # Example:
    #
    #     use Rack::Session::Memooie, :key => 'rack.session',
    #                                :domain => 'foo.com',
    #                                :path => '/',
    #                                :expire_after => 2592000,
    #                                :secret => 'change_me',
    #                                :old_secret => 'also_change_me'
    #
    #     All parameters are optional.
    #
    # @see Rack::Session::Cookie
    #
    class Memooie < ::Rack::Session::Cookie

      attr_reader :pool

      def initialize(app, options={})
        @pool = {}
        super(app, options.merge!(:cookie_only => true))
      end

      private

      def unpacked_cookie_data(env)
        env["rack.session.unpacked_cookie_data"] ||= begin
          request = Rack::Request.new(env)
          session_data = request.cookies[@key]
          if @secrets.size > 0 && session_data
            session_data, digest = session_data.split("--")
            session_data = nil unless digest_match?(session_data, digest)
          end
          all_data = coder.decode(session_data) || {}
          all_data.merge! @pool[all_data['session_id']] ||= {}
        end
      end

      def set_session(env, session_id, session, options)
        session = session.merge("session_id" => session_id)
        # filter and save the data to save in the cookie
        _data = {}
        # make sure the id exists
        @pool[session['session_id']] ||= {}
        # get the data to save for the cookie
        session.each do |k, v|
          if k == 'session_id' or k.match /padrino/
            _data[k] = v
          else
            @pool[session['session_id']][k] = v
          end
        end
        session_data = coder.encode(_data)

        if @secrets.first
          session_data << "--#{generate_hmac(session_data, @secrets.first)}"
        end

        if session_data.size > (4096 - @key.size)
          env["rack.errors"].puts("Warning! Rack::Session::Cookie data size exceeds 4K.")
          nil
        else
          session_data
        end
      end

      def destroy_session(env, session_id, options)
        @pool.delete session_id
        # Nothing to do here, data is in the client
        generate_sid unless options[:drop]
      end

    end
  end
end
