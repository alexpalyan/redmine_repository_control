require File.dirname(__FILE__) + '/../test_helper'

class RepositoryControlTest < Test::Unit::TestCase
  fixtures :repository_controls, :projects, :roles, :users

  def test_create
      repo_control = RepositoryContro.new
      repo_control.project_id = 1
      repo_control.role_id = 1
      repo_control.path = "somepath"
      repo_control.permissions = ":somepermission"
      assert repo_control.save

      repo_control.destroy
  end

  # Replace this with your real tests.
  def test_truth
    assert true
  end
end
