# -*- encoding : utf-8 -*-
class ObjectRole < ActiveRecord::Base
  ##############################################################################
  # class methods
  ##############################################################################

  def self.roles
    [ "owner" ]
  end

  # What ObjectRoles does this object have associated?
  def self.find_all_by_object(object)
    raise "Can only operate on ActiveRecord::Base objects." unless object.is_a?(ActiveRecord::Base)
    raise "Can only operate on saved objects" if object.new_record?

    klazz_name = object.class.to_s
    object_reference = object.id

    ObjectRole.find(:all, :conditions => { :klazz_name => klazz_name, :object_reference => object_reference } )
  end

  ##############################################################################
  # associations
  ##############################################################################

  belongs_to :user

  ##############################################################################
  # validations
  ##############################################################################
  
  validates_presence_of :klazz_name, :object_reference, :user_id, :role
  validates_numericality_of :object_reference, :only_integer => true
  validates_inclusion_of :role, :in => ObjectRole.roles

  ##############################################################################
  # constructor
  ##############################################################################

  ##############################################################################
  # instance methods
  ##############################################################################

  def description
    "#{self.klazz_name} #{self.object_reference}"
  end

  def object
    obj = nil

    begin
      klazz = eval(self.klazz_name)
      obj = klazz.find(self.object_reference)
    rescue
    end

    obj
  end
end
