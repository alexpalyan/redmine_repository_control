require 'redmine'

Dispatcher.to_prepare :redmine_repository_controls do
  ProjectsHelper.send(:include, RepositoryControls::ProjectsHelperPatch) unless ProjectsHelper.included_modules.include?(RepositoryControls::ProjectsHelperPatch)
end

Redmine::Plugin.register :redmine_repository_controls do
  name 'Redmine Repository Controls plugin'
  author 'Brian Knobbs'
  description 'Adds fine grained repository access control to redmine using Apache'
  url 'http://github.com/transitdk/Redmine-Repository-Control'
  version '0.1.0'

  requires_redmine :version_or_higher => '0.8.3'

  project_module :repository_controls do
    permission :manage_repository_controls, {:repository_controls => [:list, :new, :edit, :destroy]}
  end

end
