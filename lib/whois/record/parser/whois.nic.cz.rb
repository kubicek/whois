#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2012 Simone Carletti <weppos@weppos.net>
#++


require 'whois/record/parser/base'
require 'whois/record/scanners/whois.nic.cz.rb'

module Whois
  class Record
    class Parser

      #
      # = whois.nic.cz parser
      #
      # Parser for the whois.nic.cz server.
      #
      class WhoisNicCz < Base
        include Scanners::Ast

        property_supported :disclaimer do
          node "field:disclaimer"
        end

        property_supported :domain do
          node("domain") { |str| str.downcase }
        end

        property_not_supported :domain_id
        property_not_supported :referral_whois
        property_not_supported :referral_url

        property_supported :status do
          Array.wrap(node("status")).map do |line|
            case line.downcase
              when "no entries found"
                :available
              when "paid and in zone"
                :registered
              when "delete prohibited"
                :server_delete_prohibited
              when "registration renewal prohibited"
                :server_renew_prohibited
              when "sponsoring registrar change prohibited"
                :server_transfer_prohibited
              when "update prohibited"
                :server_update_prohibited
              when "registrant change prohibited"
                :server_registrant_change_prohibited
              when "registrant change forbidden"
                :server_registrant_change_forbidden
              when "domain blocked"
                :server_blocked
              when "domain is administratively kept out of zone"
                :server_out_zone_manual
              when "domain is administratively kept in zone"
                :server_in_zone_manual
              when "expired"
                :expired
              when "domain is not generated into zone"
                :out_of_zone
              when "the domain isn't generated in the zone"
                :out_of_zone
              when "the domain is administratively kept out of zone"
                :out_of_zone
              when "the domain is administratively kept in zone"
                :kept_in_zone
              when "registration renewal forbidden"
                :renewal_forbidden
              when "deletion forbidden"
                :deletion_forbidden
              when "to be deleted"
                :delete_candidate
              when "update forbidden"
                :update_forbidden
              when "sponsoring registrar change forbidden"
                :update_forbidden
              else
                Whois.bug!(ParserError, "Unknown status `#{line}'.")
            end
          end
        end

        property_supported :available? do
          !!node("status:available")
        end

        property_supported :registered? do
          !available?
        end

        property_supported :created_on do
          node("registered") { |str| Time.zone.parse(str) }
        end

        property_supported :updated_on do
          node("changed") { |str| Time.zone.parse(str) }
        end

        property_supported :expires_on do
          node("expire") { |str| Time.zone.parse(str) }
        end

        property_supported :registrar do
          node("registrar") do |str|
            Record::Registrar.new(
              :id           => str,
              :name         => str
            )
          end
        end

        property_supported :registrant_contacts do
          build_contact(node("registrant"), Whois::Record::Contact::TYPE_REGISTRANT)
        end

        property_supported :admin_contacts do
          Array.wrap(node("admin-c")).collect do |handle|
            build_contact(handle, Whois::Record::Contact::TYPE_ADMIN)
          end
        end

        property_supported :technical_contacts do
          contacts = []
          node("nsset-#{node('nsset')}") {|str| contacts << str["tech-c"]}
          contacts.flatten.collect { |c|
            build_contact(c, Whois::Record::Contact::TYPE_TECHNICAL)
          }
        end

        property_supported :nameservers do
          node("nsset-#{node('nsset')}") do |str|
            str['nserver'].flatten.map do |line|
              if line =~ /(.+) \((.+)\)/
                Record::Nameserver.new($1, *$2.split(", "))
              else
                Record::Nameserver.new(line.strip)
              end
            end
          end
        end

        # Initializes a new {Scanners::WhoisNicCz} instance
        # passing the {#content_for_scanner}
        # and calls +parse+ on it.
        #
        # @return [Hash]
        def parse
          Scanners::WhoisNicCz.new(content_for_scanner).parse
        end

      private

        def build_contact(element, type)
          node("contact-#{element}") do |str|
            address = str["address"].kind_of?(Array) ? str["address"].join("\n") : str["address"]
            Record::Contact.new(
              :id           => element,
              :type         => type,
              :name         => str["name"],
              :organization => str["org"],
              :address      => address,
              :email        => str["e-mail"],
              :phone        => str["phone"],
              :fax          => str["fax-no"],
              # :city         => address[1],
              # :zip          => address[2],
              # :state        => address[3],
              # :country_code => address[4],
              :created_on   => str["created"] ? Time.zone.parse(str["created"]) : nil,
              :updated_on   => str["Last Update"] ? Time.zone.parse(str["Last Update"]) : nil
            )
          end
        end

      end

    end
  end
end
