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
      user = options[:user] || get_current_user

      return false if basic_check_fails?(options)

      check_user(user)
      # Checks done. Let's go.

      or_ = find_object_role(object, user)

      # This time, we want it to be nil.
      if or_.nil? && !user.nil?
        klazz_name = object.class.to_s
        object_reference = object.id

        ObjectRole.create!( :klazz_name => klazz_name, :object_reference => object_reference, :user => user, :role => role )
        Rails.logger.debug("Authorizer: created authorization on #{object} for current_user with ID #{user.id} with role #{role}")
        ret = true
      end

      ret
    end

    ############################################################################
    # authorize!
    #
    # Bang version of authorize
    ############################################################################

    def self.authorize! options = {}
      auth_ok = user_is_authorized?(options)

      # User can override error message
      message = options[:message]
      # Attempt to fetch from I18n
      begin
        message ||= I18n.translate!("authorizer.access_denied")
      rescue
      end
      # Default error message
      message ||= "You are not authorized to access this resource."

      raise Authorizer::UserNotAuthorized.new(message) unless auth_ok

      auth_ok
    end

    ############################################################################
    # user_is_authorized?
    #
    # If no user is specified, current_user is used.
    ############################################################################

    def self.user_is_authorized? options = {}
      OptionsChecker.check(options, [ :object ])

      ret = false

      check = basic_check_fails?(options)
      return ret if check

      object = options[:object]
      user = options[:user] || get_current_user

      # Checks
      check_user(user)
      # Checks done. Let's go.

      or_ = find_object_role(object, user)
        
      # Congratulations, you've been Authorized.
      unless or_.nil?
        ret = true
      end

      if ret
        Rails.logger.debug("Authorizer: authorized current_user with ID #{user.id} to access #{or_.description} because of role #{or_.role}") unless user.nil? || or_.nil?
      else
        Rails.logger.debug("Authorizer: authorization failed for current_user with ID #{user.id} to access #{object.inspect}") unless user.nil? || object.nil?
      end

      ret
    end

    # Could't get alias_method to work. Don't ask me why.
    def self.authorize(options = {})
      user_is_authorized?(options)
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
      user = options[:user] || get_current_user

      # Check
      check_user(user)
      # Checks done. Let's go.

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
    # From the entire collection of Posts, return the subset that belongs to the current user.
    #
    # Arguments:
    #  - class_name: which class to use, e.g. "Post"
    #  - what: will be passed on to the ActiveRecord find function (e.g. Post.find(what))
    #  - find_options: will also be passed on (e.g. Post.find(what, find_options))
    #  - authorizer_options: options for authorizer, e.g. { :user => @user }
    ############################################################################

    def self.find(class_name, what, find_options = {}, authorizer_options = {})
      options = { :class_name => class_name, :what => what, :find_options => find_options }
      my_options = authorizer_options.merge(options) # options overrides user-specified options.

      internal_find(my_options)
    end

    ############################################################################
    # is_authorized?
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

    ############################################################################
    # internal_find
    ############################################################################
    # Extract some info from ObjectRole objects and then pass the info through
    # to the ActiveRecord finder.
    ############################################################################

    def self.internal_find(options = {})
      # Options
      OptionsChecker.check(options, [ :what, :class_name ])

      # assign
      class_name = options[:class_name]
      what = options[:what]
      find_options = options[:find_options] || {}
      user = options[:user] || get_current_user # Default is current user, but the specified user will override.

      # Check userrrrrrrrrrrr --- =====================- ---= ===-=- *&((28 @((8
      check_user(user)
      ret = nil
      # Checks done. Let's go.
      # Get the real klazz
      klazz = nil
      # Check it
      begin
        klazz = eval(class_name)
      rescue => e
        # Throw an exception if klazz is nil
        raise ArgumentError.new("Could not eval class '#{klazz}'. It presumably does not exist. Maybe you mistyped its name? Error was: #{e.inspect}") if klazz.nil?
      end
      # oooo ooo ooo ___ --- === __- --_- ++_+_ =--- +- =+=-=- =-=    <--- ice beam!
      unless klazz.nil?
        # now we know klazz really exists.
        # let's find the object_role objects that match the user and klazz.
        # Get the object_role objects
        object_roles_conditions = { :klazz_name => class_name, :user_id => user.id }
        object_roles = ObjectRole.find(:all, :conditions => object_roles_conditions )
        # OK.
        # We already have the comprehensive list of object roles we are authorized on.
        unless object_roles.nil?
          # Get a list of IDs. These are objects that are owned by the current_user
          object_role_ids = object_roles.collect { |or_| or_.object_reference } # [ 1, 1, 1, 1 ]
          # Make it at least an array if collect returns nil
          object_role_ids ||= []
          # DO IT DO IT DO IT DO IT DO IT DO IT DO IT DO IT DO IT DO IT DO IT
          # DO IT DO IT DO IT DO IT DO IT DO IT DO IT DO IT DO IT DO IT DO IT
          # DO IT DO IT DO IT DO IT DO IT DO IT DO IT DO IT DO IT DO IT DO IT
          # DO IT DO IT DO IT DO IT DO IT DO IT DO IT DO IT DO IT DO IT DO IT
          # DO IT DO IT DO IT DO IT DO IT DO IT DO IT DO IT DO IT DO IT DO IT
          # DO IT DO IT DO IT DO IT DO IT DO IT DO IT DO IT DO IT DO IT DO IT
          unless object_role_ids.nil?
            # Prepare find_options
            leading_find_options = {} # insert conventions here if needed, maybe for security or other purposes
            my_find_options = find_options.merge(leading_find_options)
            # Big chance object_role_ids equals an Empty Array (TM) or []
            # That's good, it means this line will be
            #
            # Post.scoped_by_id([]).find(:all)
            #
            # Which will never ever return anything.
            # This is also good because it means we can just proxy whatever we get from the user into Find and it will take care of it for us.
            ret = klazz.scoped_by_id(object_role_ids).find(what, my_find_options) # scoped_by is new in 2.3. sweeeeeeeeeeeet
          end
        end
      end

      ret
    end

    def self.find_object_role(object, user)
      return nil if object.nil? || user.nil?

      # Check
      check_user(user)
      # Checks done. Let's go.
    
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

      ret
    end

    def self.check_user(user)
      ret = true

      if user.nil?
        raise Authorizer::RuntimeException.new "User cannot be nil. Maybe you should specify authorizer_options = { :user => user } if you are not calling from a controller?"
      end

      unless user.is_a?(ActiveRecord::Base)
        raise Authorizer::RuntimeException.new "User must inherit from ActiveRecord::Base"

      end

      if user.new_record?
        raise Authorizer::RuntimeException.new "User must be saved"
      end

      ret
    end
  end
end
