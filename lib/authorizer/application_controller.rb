# -*- encoding : utf-8 -*-
# Use this file to add a couple of helper methods to ApplicationController

################################################################################
# Addendum to ApplicationController
################################################################################
# These methods are heavily dependent on InheritedResources, more specifically the 'resource' method.
#
# Otherwise there would be no predefined way of peeking into a controller's resource object.
################################################################################

# for user_not_authorized
require 'authorizer/exceptions'

class ApplicationController < ActionController::Base
  helper_method :own_created_object, :authorize

  private

  # Own an object (you've just created)
  # With no arguments given, this method will try to use inherited_resources to determine the object you've just created.
  # The object can be overridden with :object => object
  def own_created_object(options = {})
    ret = false # default answer: don't allow

    r = options[:object]

    begin
      r ||= resource
    rescue
    end

    unless r.nil?
      # only if this objet was successfully created will we do this.
      unless r.new_record?
        ret = Authorizer::Base.authorize_user( :object => r )
      end
    end

    ret
  end

  # Authorize on the current object.
  # With no arguments given, this method will try to use inherited_resources to determine the object you're supposed to authorize on.
  # The object can be overridden with :object => object
  def authorize(options = {})
    ret = false # return false by default, effectively using a whitelist method.

    r = options[:object]

    begin
      r ||= resource
    rescue      
    end

    unless r.nil?
      # Use the bang method, it will raise an Exception if needed
      ret = Authorizer::Base.authorize!( :object => r )
    end

    ret
  end
end

