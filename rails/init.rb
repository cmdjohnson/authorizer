################################################################################
# init.rb
#
# This file will load the Observers we need to prevent the database from becoming clogged with stale authorization objects.
################################################################################

config.after_initialize do
  ActiveRecord::Base.observers << Authorizer::UserObserver
  ActiveRecord::Base.observers << Authorizer::ObjectObserver
end
