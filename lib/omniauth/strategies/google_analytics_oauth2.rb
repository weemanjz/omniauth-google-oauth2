require 'omniauth/strategies/oauth2'

module OmniAuth
  module Strategies
    class GoogleAnalyticsOauth2 < OmniAuth::Strategies::GoogleOauth2
      DEFAULT_SCOPE = 'userinfo.profile,analytics.readonly'

      option :name, 'google_analytics'

      def authorize_params
        super.tap do |params|
          if [nil, ''].include?(request.params['scope'])
            scope_list = DEFAULT_SCOPE.split(' ').map { |item| item.split(',') }.flatten
            scope_list.map! { |s| s =~ /^https?:\/\// ? s : "#{BASE_SCOPE_URL}#{s}" }
            params[:scope] = scope_list.join(' ')
          end
          params[:access_type] = 'offline'
          params[:prompt] = 'consent'
        end
      end
    end
  end
end
