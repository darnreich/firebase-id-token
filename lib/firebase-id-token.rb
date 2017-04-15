# encoding: utf-8
# Copyright 2012 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

##
# Validates strings alleged to be ID Tokens issued by Google; if validation
#  succeeds, returns the decoded ID Token as a hash.
# It's a good idea to keep an instance of this class around for a long time,
#  because it caches the keys, performs validation statically, and only
#  refreshes from Google when required (once per day by default)
#
# @author Tim Bray, adapted from code by Bob Aman

require 'multi_json'
require 'jwt'
require 'openssl'
require 'net/http'

module FirebaseIDToken
  class CertificateError < StandardError; end
  class ValidationError < StandardError; end
  class ExpiredTokenError < ValidationError; end
  class SignatureError < ValidationError; end
  class InvalidIssuerError < ValidationError; end
  class AudienceMismatchError < ValidationError; end
  class ClientIDMismatchError < ValidationError; end

  class Validator

    def do_sth
      print 'Hello GEM!!!!'
    end

    FIREBASE_CERTS_URI = 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com'
    FIREBASE_CERTS_EXPIRY = 86400 # 1 day

    FIREBASE_ISSUERS_PREFIX = 'https://securetoken.google.com/'

    def initialize(keyopts = {})
      if keyopts[:x509_cert]
        @certs_mode = :literal
        @certs = { :_ => keyopts[:x509_cert] }
      # elsif keyopts[:jwk_uri]  # TODO
      #   @certs_mode = :jwk
      #   @certs = {}
      else
        @certs_mode = :old_skool
        @certs = {}
      end

      @certs_expiry = keyopts.fetch(:expiry, FIREBASE_CERTS_EXPIRY)
    end

    ##
    # If it validates, returns a hash with the JWT payload from the ID Token.
    #  You have to provide an "aud" value, which must match the
    #  token's field with that name.
    #  Furthermore the tokens field "iss" must be
    #  "https://securetoken.google.com/<aud>"
    #
    # If something fails, raises an error
    #
    # @param [String] token
    #   The string form of the token
    # @param [String] aud
    #   The required audience value
    #
    # @return [Hash] The decoded ID token
    def check(token, aud)
      payload = check_cached_certs(token, aud)

      unless payload
        # no certs worked, might've expired, refresh
        if refresh_certs
          payload = check_cached_certs(token, aud)

          unless payload
            raise SignatureError, 'Token not verified as issued by Firebase'
          end
        else
          raise CertificateError, 'Unable to retrieve Firebase public keys'
        end
      end

      payload
    end

    private

    # tries to validate the token against each cached cert.
    # Returns the token payload or raises a ValidationError or
    #  nil, which means none of the certs validated.
    def check_cached_certs(token, aud)
      payload = nil

      # find first public key that validates this token
      @certs.detect do |key, cert|
        begin
          public_key = cert.public_key
          decoded_token = JWT.decode(token, public_key, true, { :algorithm => 'RS256' })
          payload = decoded_token.first

          payload
        rescue JWT::ExpiredSignature
          raise ExpiredTokenError, 'Token signature is expired'
        rescue JWT::DecodeError => e
          nil # go on, try the next cert
        end
      end

      if payload
        if !(payload.has_key?('aud') && payload['aud'] == aud)
          raise AudienceMismatchError, 'Token audience mismatch'
        end
        if FIREBASE_ISSUERS_PREFIX + aud != payload['iss']
          raise InvalidIssuerError, 'Token issuer mismatch'
        end
        payload
      else
        nil
      end
    end

    # returns false if there was a problem
    def refresh_certs
      case @certs_mode
      when :literal
        true # no-op
      when :old_skool
        old_skool_refresh_certs
      end
    end

    def old_skool_refresh_certs
      return true unless certs_cache_expired?

      uri = URI(FIREBASE_CERTS_URI)
      get = Net::HTTP::Get.new uri.request_uri
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      res = http.request(get)

      if res.is_a?(Net::HTTPSuccess)
        new_certs = Hash[MultiJson.load(res.body).map do |key, cert|
                           [key, OpenSSL::X509::Certificate.new(cert)]
                         end]
        @certs.merge! new_certs
        @certs_last_refresh = Time.now
        true
      else
        false
      end
    end

    def certs_cache_expired?
      if defined? @certs_last_refresh
        Time.now > @certs_last_refresh + @certs_expiry
      else
        true
      end
    end
  end
end
