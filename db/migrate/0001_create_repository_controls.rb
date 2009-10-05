class CreateRepositoryControls < ActiveRecord::Migration
  def self.up
    create_table :repository_controls do |t|
      t.column :project_id, :integer
      t.column :role_id, :integer
      t.column :path, :string
      t.column :permissions, :text
    end
  end

  def self.down
    drop_table :repository_controls
  end
end
