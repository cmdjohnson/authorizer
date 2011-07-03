module Authorizer
  ############################################################################
  # helper class that does administrative functions for you
  ############################################################################
  class Admin < Base
    # not everybody uses "User" as user class name. We do :o -=- :))) ffFF  ww ppO :)))
    @@user_class_name = "User"

    ############################################################################
    # create_brand_new_object_roles
    #
    # For if you've been working without Authorizer and want to start using it.
    # Obviously, if you don't have any ObjectRoles then you'll find yourself blocked out of your own app.
    # This method will assign all objects listed in an array to a certain user.
    # For instance:
    #
    # user = User.find(1)
    # objects = [ "Post", "Category" ]
    # Authorizer::Admin.create_brand_new_object_roles( :user => user, :objects => objects )
    #
    # If objects is not specified, Admin will look for all descendants of ActiveRecord::Base
    # and exclude the ObjectRole and User classes.
    #
    # Authorizer::Admin.create_brand_new_object_roles( :user => user )
    ############################################################################

    def self.create_brand_new_object_roles(options = {})
      OptionsChecker.check(options, [ :user ])

      objects = gather_direct_descendants_of_activerecord_base || options[:objects]

      ret = false

      raise "objects must be an Array" unless objects.is_a?(Array)

      # Nothing to do ..
      return ret if objects.blank?

      begin
        user_id = options[:user].id
      rescue
      end

      unless user_id.nil?
        for object in objects
          evaled_klazz = nil

          begin
            evaled_klazz = eval(object)
          rescue
          end

          unless evaled_klazz.nil?
            # One is enough to return exit status OK.
            ret = true
            # Let's find all. This is the same as Post.all
            if evaled_klazz.is_a?(Class)
              collection = evaled_klazz.all

              # Go
              unless collection.blank?
                for coll_ in collection
                  ObjectRole.create!( :klazz_name => object, :object_reference => coll_.id, :user_id => user_id, :role => "owner" )
                end
              end
            end
          end
        end
      end

      ret
    end

    ############################################################################
    # remove_all_unused_authorization_objects
    #############################################################################
    # Remove all stale (non-object) authorization objects.
    ############################################################################

    def self.remove_all_unused_authorization_objects options = {}
      # no options
      # ___
      # Let's iterate all ObjectRoles
      for object_role in ObjectRole.all
        object_role.destroy if object_role.object.nil?
      end
    end

    protected

    ############################################################################
    # gather_direct_descendants_of_activerecord_base
    ############################################################################

    def self.gather_direct_descendants_of_activerecord_base
      ret = []

      classes = ActiveRecord::Base.send(:subclasses)

      # Go through it twice to determine direct descendants
      for klazz in classes
        # Push the class name, not the class object itself.
        klazz_name = klazz.to_s
        # May never use the ObjectRole or User class.
        ret.push klazz_name if !klazz_name.eql?("ObjectRole") && !klazz_name.eql?(@@user_class_name)
      end

      ret
    end
  end
end
