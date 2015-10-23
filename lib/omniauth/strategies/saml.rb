require 'omniauth'
require 'ruby-saml'

module OmniAuth
  module Strategies
    class SAML
      include OmniAuth::Strategy

      option :name_identifier_format, nil
      option :idp_sso_target_url_runtime_params, {}
      option :request_attributes, [
        { name: 'email', name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', friendly_name: 'Email address' },
        { name: 'name', name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', friendly_name: 'Full name' },
        { name: 'first_name', name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', friendly_name: 'Given name' },
        { name: 'last_name', name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', friendly_name: 'Family name' }
      ]
      option :attribute_service_name, 'Required attributes'

      def saml_settings
        OneLogin::RubySaml::Settings.new(options).tap do |settings|
          settings.assertion_consumer_service_url ||= callback_url

          if options.request_attributes.length > 0
            settings.attribute_consuming_service.service_name options.attribute_service_name
            options.request_attributes.each do |attribute|
              settings.attribute_consuming_service.add_attribute attribute
            end
          end
        end
      end

      def request_phase
        redirect(saml_authn_request.create(saml_settings, runtime_request_parameters))
      end

      def saml_authn_request
        OneLogin::RubySaml::Authrequest.new
      end

      def runtime_request_parameters
        params = request.params
        options.idp_sso_target_url_runtime_params.each_with_object({}) do |(param_key, request_key), result|
          result[request_key] = params[param_key.to_s] if params.has_key?(param_key.to_s)
        end
      end

      def callback_phase
        unless request.params['SAMLResponse']
          raise OmniAuth::Strategies::SAML::ValidationError.new("SAML response missing")
        end

        # Call a fingerprint validation method if there's one
        if options.idp_cert_fingerprint_validator
          fingerprint_exists = options.idp_cert_fingerprint_validator[response_fingerprint]
          unless fingerprint_exists
            raise OmniAuth::Strategies::SAML::ValidationError.new("Non-existent fingerprint")
          end
          # id_cert_fingerprint becomes the given fingerprint if it exists
          options.idp_cert_fingerprint = fingerprint_exists
        end

        response = OneLogin::RubySaml::Response.new(request.params['SAMLResponse'], settings: saml_settings)
        response.attributes['fingerprint'] = options.idp_cert_fingerprint

        @name_id = response.name_id
        @attributes = response.attributes

        if @name_id.nil? || @name_id.empty?
          raise OmniAuth::Strategies::SAML::ValidationError.new("SAML response missing 'name_id'")
        end

        # will raise an error since we are not in soft mode
        response.soft = false
        response.is_valid?

        super
      rescue OmniAuth::Strategies::SAML::ValidationError
        fail!(:invalid_ticket, $!)
      rescue OneLogin::RubySaml::ValidationError
        fail!(:invalid_ticket, $!)
      end

      # Obtain an idp certificate fingerprint from the response.
      def response_fingerprint
        response = request.params['SAMLResponse']
        response = (response =~ /^</) ? response : Base64.decode64(response)
        document = XMLSecurity::SignedDocument::new(response)
        cert_element = REXML::XPath.first(document, "//ds:X509Certificate", { "ds"=> 'http://www.w3.org/2000/09/xmldsig#' })
        base64_cert = cert_element.text
        cert_text = Base64.decode64(base64_cert)
        cert = OpenSSL::X509::Certificate.new(cert_text)
        Digest::SHA1.hexdigest(cert.to_der).upcase.scan(/../).join(':')
      end

      def other_phase
        if on_path?("#{request_path}/metadata")
          # omniauth does not set the strategy on the other_phase
          @env['omniauth.strategy'] ||= self
          setup_phase

          response = OneLogin::RubySaml::Metadata.new
          Rack::Response.new(response.generate(saml_settings), 200, { "Content-Type" => "application/xml" }).finish
        else
          call_app!
        end
      end

      uid { @name_id }

      info do
        {
          :name  => @attributes[:name],
          :email => @attributes[:email] || @attributes[:mail],
          :first_name => @attributes[:first_name] || @attributes[:firstname] || @attributes[:firstName],
          :last_name => @attributes[:last_name] || @attributes[:lastname] || @attributes[:lastName]
        }
      end

      extra { { :raw_info => @attributes } }
    end
  end
end

OmniAuth.config.add_camelization 'saml', 'SAML'
