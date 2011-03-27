module Warden
  module Facebook
    class Strategy < Warden::Strategies::Base
      def params
        @params ||= Rack::Utils.parse_query(request.query_string)
      end

      def authenticate!
        if params['code']
          success! facebook_user(params['code'])
        else
          throw(:halt, [302, {'Location' => authorize_url}, []])
        end
      end

      private
      def facebook_user(code)
        access_token = access_token_for(code)
        data = JSON.parse(access_token.get('/me'))
        make_user(data, access_token.token)
      rescue OAuth2::HTTPError
        error_page($!)
      end

      def make_user(data, token)
        Warden::Facebook::User.new(data, token)
      end

      def oauth_client
        oauth_proxy.client
      end

      def authorize_url
        oauth_proxy.authorize_url
      end

      def access_token_for(code)
        oauth_proxy.access_token_for(code)
      end

      def oauth_proxy
        @oauth_proxy ||= Warden::Facebook::Proxy.new(env['warden'].config[:facebook_app_id],
                                                     env['warden'].config[:facebook_app_secret],
                                                     env['warden'].config[:facebook_scopes],
                                                     callback_url)
      end

      def callback_url
        absolute_url(request, env['warden'].config[:facebook_callback_url])
      end

      def absolute_url(request, suffix = nil)
        port_part = case request.scheme
                    when "http"
                      request.port == 80 ? "" : ":#{request.port}"
                    when "https"
                      request.port == 443 ? "" : ":#{request.port}"
                    end
        "#{request.scheme}://#{request.host}#{port_part}#{suffix}"
      end

      def error_page(exception)
        %(<p>Outdated code <code>#{params['code']}</code>:</p><pre><code>#{exception}</code></pre><p><a href="/auth/facebook">Retry</a></p>)
      end
    end
  end
end

Warden::Strategies.add(:facebook, Warden::Facebook::Strategy)
