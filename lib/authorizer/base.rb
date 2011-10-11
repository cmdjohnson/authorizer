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
    # Authorize the current user (retrieved by calling current_user on the object passed using the :object parameter.
    # The user can also be explicly spcified using :user.
    # If no :role is specified, "owner" is used.
    # 
    # Params:
    #  - :user (default: current_user)
    #  - :object
    #  - :role
    #
    # Example: Authorizer::Base.authorize_user :object => object
    def self.authorize_user(options = {})
      ret = false

      object = options[:object]
      role = options[:role] || "owner"
      user = options[:user] || get_current_user
      
      # User can specify the object using a block, too.
      if block_given?
        object = yield
      end

      return false if basic_check_fails?(options)

      check_user(user)
      # Checks done. Let's go.

      if !object.nil? && !user.nil?
        or_ = find_object_role(object, user)
      end

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

    # Return true if a user is authorized to act upon this object. Raises Authorizer::UserNotAuthorized upon failure. 
    # Params:
    # - :user (default: current_user)
    # - :object
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

    # Return true if a user is authorized to act upon this object. Return false if this is not the case.
    # Params:
    # - :user (default: current_user)
    # - :object
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

    # Return true if a user is authorized to act upon this object. Return false if this is not the case.
    # Synonym for user_is_authorized?
    # Params:
    # - :user (default: current_user)
    # - :object
    def self.authorize(options = {})
      user_is_authorized?(options) # Could't get alias_method to work. Don't ask me why.
    end

    # Remove authorization from a certain object. Returns true upon success and false upon failure.
    # Params:
    # - :user (default: current_user)
    # - :object
    def self.remove_authorization options = {}
      OptionsChecker.check(options, [ :object ])

      ret = false

      return ret if basic_check_fails?(options)

      object = options[:object]
      user = options[:user] || get_current_user

      # Check
      check_user(user)
      # Checks done. Let's go.

      unless user.nil?
        or_ = find_object_role(object, user)
      end

      unless or_.nil?
        Rails.logger.debug("Authorizer: removed authorization for user ID #{user.id} on #{or_.description}")

        or_.destroy

        ret = true
      end

      ret
    end
    
    # From the entire collection of Posts in the database, return the number of Posts that belong to the current user.
    # Returns nil upon failure, returns a positive integer or 0 on success.
    def self.count(class_name, options = {})
      ret = nil
      
      user = options[:user] || get_current_user
      find_options = options[:find_options] || {}
      
      if !class_name.blank? && !user.blank?
        begin
          ret = Authorizer::Base.find(class_name, :all, find_options, { :user => user }).count
        rescue => e
          Rails.logger.warn("#{__FILE__}: #{__LINE__}: Failed to count objects for class_name '#{class_name}' for user #{user.inspect}. Error was: #{e}")
        end
      end
      
      ret
    end

    # From the entire collection of Posts, return the subset that belongs to the current user.
    #
    # Arguments:
    #  - class_name: which class to use, e.g. "Post"
    #  - what: will be passed on to the ActiveRecord find function (e.g. Post.find(what))
    #  - find_options: will also be passed on (e.g. Post.find(what, find_options))
    #  - authorizer_options: options for authorizer, e.g. { :user => @user }
    def self.find(class_name, what, find_options = {}, authorizer_options = {})
      options = { :class_name => class_name, :what => what, :find_options => find_options }
      my_options = authorizer_options.merge(options) # options overrides user-specified options.

      internal_find(my_options)
    end

    # Return true if a user is authorized to act upon this object. Return false if this is not the case.
    # Synonym for user_is_authorized
    # 
    # This method's only parameter is the object to be checked for authorization so you don't have to type :object => object.
    def self.is_authorized? object
      user_is_authorized? :object => object
    end

    # Shortcut for user_is_authorized. Takes the actual object as a parameter instead of a Hash.
    def self.create_ownership object
      ret = false

      return ret if basic_check_fails?(object)

      ret = authorize_user( :object => object )

      ret
    end

    protected
    
    ############################################################################
    # get_topmost_class
    ############################################################################
    # Get the topmost class for the given class, not going higher up the tree
    # than ActiveRecord::Base or Object
    ############################################################################
    
    def self.get_topmost_class(klazz)
      raise "Please provide me with a Class object." unless klazz.is_a?(Class)
      
      top_klazz = klazz
      next_top_klazz = nil
      
      begin
        next_top_klazz = top_klazz.superclass
      rescue
      end
      
      if next_top_klazz
        until next_top_klazz.eql?(ActiveRecord::Base) || next_top_klazz.eql?(Object)
          top_klazz = next_top_klazz
          next_top_klazz = top_klazz.superclass
        end
      end
      
      top_klazz
    end
    
    ############################################################################
    # array_of_string_subclasses
    ############################################################################
    # Call the protected 'subclasses' method and convert all class names to string.
    ############################################################################
    
    def self.array_of_string_subclasses(klazz)
      raise "Need a Class object." unless klazz.is_a?(Class)
      
      ret = []
      
      for c in klazz.subclasses
        ret.push(c.to_s)
      end
      
      # Also, we must include the class itself.
      ret.push(klazz.to_s)
      
      ret
    end

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
      # Ok, Check it ... but ...
      # If no user is found, let's leave it up to the auth solution to redirect the user to a login page.
      unless user.nil?
        begin
          klazz = eval(class_name)
        rescue => e
          # No need to throw this exception here. Just log the error.
          # It would appear whenever Authorizer was used when a user isn't logged in. 
          # That just is too much ...
          s = "Could not eval class '#{class_name}'. It presumably does not exist. Maybe you mistyped its name? Error was: #{e.inspect}"
          #raise ArgumentError.new(s) if klazz.nil?
          Rails.logger.warn("#{__FILE__}: #{__LINE__}: " + s)
        end
      end
      # oooo ooo ooo ___ --- === __- --_- ++_+_ =--- +- =+=-=- =-=    <--- ice beam!
      unless klazz.nil?
        # now we know klazz really exists.
        # This class might be some subclass. Let's find out what the topmost class is.
        topmost_class = get_topmost_class(klazz)
        # Get an array that contains all subclasses of the topmost class
        subclasses_of_topmost_class = array_of_string_subclasses(topmost_class)
        # let's find the object_role objects that match the user and klazz.
        # Get the object_role objects
        object_roles_conditions = { :user_id => user.id }
        object_roles = ObjectRole.find_all_by_klazz_name(subclasses_of_topmost_class, :conditions => object_roles_conditions )
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

    # Find the ObjectRole record that matches object (first argument) and user (second argument).
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
      
      # YES YES I know it's a good habit to check for current_user, but I've decided not to raise anything 
      # and make this method basically void.
      # Why?
      # Let the auth mechanism redirect the user if no user is present.
      # I think that's the proper way to do things.

      #      if user.nil?
      #        raise Authorizer::RuntimeException.new "User cannot be nil. Maybe you should specify authorizer_options = { :user => user } if you are not calling from a controller?"
      #      end
      #
      #      unless user.is_a?(ActiveRecord::Base)
      #        raise Authorizer::RuntimeException.new "User must inherit from ActiveRecord::Base"
      #      end
      #
      #      if user.new_record?
      #        raise Authorizer::RuntimeException.new "User must be saved"
      #      end

      ret
    end
  end
end
