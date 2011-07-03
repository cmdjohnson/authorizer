# -*- encoding : utf-8 -*-
################################################################################
# Authorizer
#
# Authorizer is a Ruby class that authorizes using the ObjectRole record.
################################################################################

# for user_not_authorized
require 'authorizer/exceptions'
require 'authorizer/application_controller'

module Authorizer
  class Base < ApplicationController
    ############################################################################
    # authorize_user
    #
    # If no user is specified, authorizes the current user.
    # If no role is specified, "owner" is used as role.
    ############################################################################

    def self.authorize_user(options)
      OptionsChecker.check(options, [ :object ])

      ret = false

      object = options[:object]
      role = options[:role] || "owner"
      user = get_current_user

      return false if basic_check_fails?(options)

      or_ = find_object_role(object, user)

      # This time, we want it to be nil.
      if or_.nil? && !user.nil?
        klazz_name = object.class.to_s
        object_reference = object.id

        ObjectRole.create!( :klazz_name => klazz_name, :object_reference => object_reference, :user => user, :role => role )
        Rails.logger.debug("Authorizer: created authorization on #{object} for current_user with ID #{user.id} witih role #{role}")
        ret = true
      end

      ret
    end

    ############################################################################
    # user_is_authorized?
    #
    # If no user is specified, current_user is used.
    ############################################################################

    def self.user_is_authorized? options
      OptionsChecker.check(options, [ :object ])

      ret = false

      check = basic_check_fails?(options)
      return ret if check

      object = options[:object]
      user = get_current_user

      or_ = find_object_role(object, user)
        
      # Congratulations, you've been Authorized.
      unless or_.nil?
        ret = true
      end

      if ret
        Rails.logger.debug("Authorizer: authorized current_user with ID #{user.id} to access #{or_.description} because of role #{or_.role}") unless user.nil? || or_.nil?
      else
        Rails.logger.debug("Authorizer: authorization failed for current_user with ID #{user.id} to access #{object.to_s}") unless user.nil? || object.nil?
      end

      ret
    end

    ############################################################################
    # remove_authorization
    ############################################################################
    # Remove authorization a user has on a certain object.
    ############################################################################

    def self.remove_authorization options = {}
      OptionsChecker.check(options, [ :object ])

      ret = false

      return ret if basic_check_fails?(options)

      object = options[:object]
      user = get_current_user

      or_ = find_object_role(object, user)

      unless or_.nil?
        Rails.logger.debug("Authorizer: removed authorization for user ID #{user.id} on #{or_.description}")

        or_.destroy

        ret = true
      end

      ret
    end

    ############################################################################
    # find
    ############################################################################
    # Out of the collection of all Posts, return the subset that belongs to the current user.
    # Use :conditions => { :order => "ASC" } to specify additional SQL conditions.
    ############################################################################

    def self.find(mode, klazz_name, options = {})
      my_options = options

      my_options[:mode] = mode
      my_options[:klazz_name] = klazz_name

      internal_find(my_options)
    end

    ############################################################################
    # is_authorized?
    #
    # Checks if the corresponding role.eql?("owner")
    ############################################################################

    def self.is_authorized? object
      user_is_authorized? :object => object
    end

    ############################################################################
    # create_ownership
    #
    # ObjectRole.create!( :klazz_name => object.class.to_s, :object_reference => object.id, :user => current_user, :role => "owner" )
    ############################################################################

    def self.create_ownership object
      ret = false

      return ret if basic_check_fails?(object)

      ret = authorize_user( :object => object )

      ret
    end

    protected

    ############################################################################
    # get_current_user
    ############################################################################
    # helper method to not be dependent on the current_user method
    ############################################################################

    def self.get_current_user
      ret = nil

      begin
        session = UserSession.find
        ret = session.user
      rescue
      end

      ret
    end

    def self.internal_find(options = {})
      # Options
      OptionsChecker.check(options, [ :mode, :klazz_name ])

      # assign
      mode = options[:mode]
      klazz_name = options[:klazz_name]
      custom_conditions = options[:conditions] || {}

      # rrrr
      ret = nil
      # Checks
      raise "Mode must be one of [ :all, :first ]" unless [ :all, :first ].include?(mode)
      # Get the real klazz
      klazz = nil
      # Check it
      begin
        klazz = eval(klazz_name)
      rescue
      end
      # oooo ooo ooo ___ --- === __- --_- ++_+_ =--- +- =+=-=- =-=    <--- ice beam!
      unless klazz.nil?
        # now we know klazz really exists.
        # let's find the object_role objects that match the current user and klaz.
        user = get_current_user
        # Get the object_role objects
        leading_conditions = { :klazz_name => klazz_name, :user_id => user.id }
        conditions = custom_conditions.merge(leading_conditions)
        object_roles = ObjectRole.find(:all, :conditions => conditions )
        # Get a list of IDs. These are objects that are owned by the current_user
        object_role_ids = object_roles.collect { |or_| or_.object_reference } # [ 1, 1, 1, 1 ]
        # There have to be some object_roles at least.
        unless object_roles.blank?
          # if statement
          if mode.eql?(:all)
            ret = klazz.find(:all, object_role_ids)
          elsif mode.eql?(:first)
            ret = klazz.find(object_role_ids.first)
          end
        end
      end

      ret
    end

    def self.find_object_role(object, user)
      klazz_name = object.class.to_s
      object_reference = object.id

      unless user.nil?
        or_ = ObjectRole.first( :conditions => { :klazz_name => klazz_name, :object_reference => object_reference, :user_id => user.id } )
      end

      or_
    end

    def self.basic_check_fails?(options)
      ret = false

      unless options[:object].nil?
        if !options[:object].is_a?(ActiveRecord::Base) || options[:object].new_record?
          raise "object must be subclass of ActiveRecord::Base and must also be saved."
        end
      end

      unless options[:user].nil?
        raise "User object must be saved" if !options[:user].is_a?(ActiveRecord::Base) || options[:user].new_record?
      end

      ret
    end
  end
end
