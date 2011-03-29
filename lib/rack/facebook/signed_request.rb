require 'openssl'
require 'base64'
require 'yajl'

#
# Gemified and borrowed heavily from Ole Riesenberg:
# http://oleriesenberg.com/2010/07/22/facebook-graph-api-with-fbml-canvas-apps.html
#
module Rack
  module Facebook
    class SignedRequest
      def initialize(app, options, &condition)
        @app = app
        @condition = condition
        @options = options
      end

      def secret
        @options.fetch(:secret)
      end

      def call(env)
        request = Rack::Request.new(env)
        signed_request = request.params.delete('signed_request')
        unless signed_request.nil?
          signature, signed_params = signed_request.split('.')

          unless signed_request_is_valid?(secret, signature, signed_params)
            return Rack::Response.new(["Invalid signature"], 400).finish
          end

          signed_params = Yajl::Parser.new.parse(base64_url_decode(signed_params))

          # add JSON params to request
          request.params['facebook'] = {}
          signed_params.each do |k,v|
            request.params['facebook'][k] = v
          end

          # e.g. to use Rack::Cache for storing this request
          request.params["facebook"]["original_method"] = env["REQUEST_METHOD"]
          env["REQUEST_METHOD"] = 'GET' if @options[:post_to_get]
          env.delete("HTTP_CACHE_CONTROL") if @options[:delete_facebook_cache_control]

        end
        @app.call(env)
      end

      private

        def signed_request_is_valid?(secret, signature, params)
          signature = base64_url_decode(signature)
          expected_signature = OpenSSL::HMAC.digest('SHA256', secret, params.tr("-_", "+/"))
          return signature == expected_signature
        end

        def base64_url_decode(str)
          str = str + "=" * (6 - str.size % 6) unless str.size % 6 == 0
          return Base64.decode64(str.tr("-_", "+/"))
        end
    end
  end
end
