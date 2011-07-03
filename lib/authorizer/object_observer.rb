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
  end
end
