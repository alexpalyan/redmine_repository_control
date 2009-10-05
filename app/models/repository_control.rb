class RepositoryControl < ActiveRecord::Base
    unloadable
    belongs_to :project
    belongs_to :role
    belongs_to :user

    serialize :permissions, Array

    def permissions
        read_attribute(:permissions) || []
    end

    def permissions=(perms)
        perms = perms.collect {|p| p.to_sym unless p.blank? }.compact.uniq if perms
        write_attribute(:permissions, perms)
    end

    def add_permission!(*perms)
        self.permissions = [] unless permissions.is_a?(Array)

        permissions_will_change!
        perms.each do |p|
            p = p.to_sym
            permissions << p unless permissions.include?(p)
        end
        save!
    end

    def remove_permission!(*perms)
        return unless permissions.is_a?(Array)
        permissions_will_change!
        perms.each { |p| permissions.delete(p.to_sym) }
        save!
    end

    # Returns true if the role has the given permission
    def has_permission?(perm)
        !permissions.nil? && permissions.include?(perm.to_sym)
    end

end
