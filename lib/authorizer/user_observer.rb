# -*- encoding : utf-8 -*-
module Authorizer
  # Observes users and deleted any associated ObjectRole objects when the user gets deleted.
  class UserObserver < ActiveRecord::Observer
    # Observe this.
    observe :user

    # W DONT DO DIZ
    # let's use before_destroy instead of after_destroy. More chance it will still have an ID >:)))))))))) :') :DDDDDDDDDDDDDDDDDDDDDDD
    # W DONT DO DIZ
    def after_destroy(user)
      # Default
      object_roles = []
      # Find all ObjectRole records that point to this user's ID.
      begin
        object_roles = ObjectRole.find_all_by_user_id(user.id)
      rescue
      end
      # Walk through 'em
      # Not executed if anything happens (array.size = 0)
      for object_role in object_roles
        object_role.destroy
      end
    end
  end
end
