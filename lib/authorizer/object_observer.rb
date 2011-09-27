# -*- encoding : utf-8 -*-
module Authorizer
  # Observes users and deleted any associated ObjectRole objects when the user gets deleted.
  class ObjectObserver < ActiveRecord::Observer
    # Observe this.
    observe ActiveRecord::Base

    # W DONT DO DIZ
    # let's use before_destroy instead of after_destroy. More chance it will still have an ID >:)))))))))) :') :DDDDDDDDDDDDDDDDDDDDDDD
    # W DONT DO DIZ
    def after_destroy(object)
      return nil if object.is_a?(User) # Users are covered by the other observer class.
      # Find all ObjectRole records that point to this object.
      object_roles = ObjectRole.find_all_by_object(object)
      # Walk through 'em
      for object_role in object_roles
        object_role.destroy
      end
    end
    
    # This is a Rails only feature:
    # Single Table Inheritance (STI) is implemented using the Type column.
    # The 'type' column contains the name of the subclass of the table the record is in.
    # For example, Dog is a subclass of Animal.
    # If we have a Dog object here that changes its 'type' to Animal, the ObjectRole must be updated to reflect the new class name.
    def after_update(object)
      type = object.try(:read_attribute, :type)
      # Big chance the object doesn't even have the 'type' attribute. In that case, do nothing.
      unless type.blank?
        object_class_name = object.class.to_s
        # This is how we gonna detect that the type has changed:
        # object_class_name should be different than type.
        unless type.eql?(object_class_name)
          object_roles = ObjectRole.find_all_by_object(object)
          # Walk through the object roles associated with this object
          for object_role in object_roles
            # update it!
            # it should reflect the new type.
            object_role.update_attributes!( :klazz_name => type )
          end
        end
      end
    end
  end
end
