# -*- encoding : utf-8 -*-
module Authorizer
  # Thrown when the user is not authorized.
  class UserNotAuthorized < Exception
  end

  # Thrown when an internal error occurs, such as when an ObjectRole record doesn't exist.
  class RuntimeException < Exception
  end
end
