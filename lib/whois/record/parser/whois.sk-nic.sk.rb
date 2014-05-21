#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2012 Simone Carletti <weppos@weppos.net>
#++


require 'whois/record/parser/base'


module Whois
  class Record
    class Parser

      #
      # = whois.sk-nic.sk parser
      #
      # Parser for the whois.sk-nic.sk server.
      #
      # NOTE: This parser is just a stub and provides only a few basic methods
      # to check for domain availability and get domain status.
      # Please consider to contribute implementing missing methods.
      # See WhoisNicIt parser for an explanation of all available methods
      # and examples.
      #
      class WhoisSkNicSk < Base

        # == Values for Status
        #
        # @see https://www.sk-nic.sk/documents/stavy_domen.html
        # @see http://www.inwx.de/en/sk-domain.html
        #
        property_supported :status do
          if content_for_scanner =~ /^Domain-status\s+(.+)\n/
            case $1.downcase
            # The domain is registered and paid.
            when  "dom_ok"    then :registered
            # The domain is registered and registration fee has to be payed (14 days).
            # Replacement 14-day period for domain payment.
            when  "dom_ta"    then :registered
            # 28 days before the expiration of one year's notice is sent to the first call for an extension of domains.
            # The domain is still fully functional (14 days).
            when  "dom_dakt"  then :registered
            # 14 days before the expiration of one year's notice is sent to the second call to the extension of domains.
            # The domain is still fully functional (14 days).
            when  "dom_warn"  then :registered
            # The domain is expired and has not been renewed (14 days).
            when  "dom_lnot"  then :registered
            when  "dom_exp"   then :expired
            # The domain losts its registrar (28 days).
            when  "dom_held"  then :redemption
            else
              Whois.bug!(ParserError, "Unknown status `#{$1}'.")
            end
          else
            :available
          end
        end

        property_supported :available? do
          !!(content_for_scanner =~ /^Not found/)
        end

        property_supported :registered? do
          !available?
        end

        property_not_supported :created_on

        property_supported :updated_on do
          if content_for_scanner =~ /^Last-update\s+(.+)\n/
            Time.parse($1)
          end
        end

        property_supported :expires_on do
          if content_for_scanner =~ /^Valid-date\s+(.+)\n/
            Time.parse($1)
          end
        end

        property_supported :registrar do
          id = content_for_scanner.match(/^Tech-id\s+(.+)\n/)[1] rescue nil
          name = content_for_scanner.match(/^Tech-name\s+(.+)\n/)[1] rescue nil

          Record::Registrar.new(
            :id   => id,
            :name => name
          )
        end

        property_supported :registrant_contacts do
          id = content_for_scanner.match(/^Admin-id\s+(.+)\n/)[1] rescue nil
          name = content_for_scanner.match(/^Admin-name\s+(.+)\n/)[1] rescue nil
          address = content_for_scanner.match(/^Admin-address\s+(.+)\n/)[1] rescue nil
          phone = content_for_scanner.match(/^Admin-telephone\s+(.+)\n/)[1] rescue nil
          email = content_for_scanner.match(/^Admin-email\s+(.+)\n/)[1] rescue nil

          [
            Record::Contact.new(
              :id       => id,
              :name     => name,
              :address  => address,
              :phone    => phone,
              :email    => email
            )
          ]
        end

        property_supported :nameservers do
          content_for_scanner.scan(/dns_name\s+(.+)\n/).flatten.map do |name|
            Record::Nameserver.new(name)
          end
        end

      end

    end
  end
end
