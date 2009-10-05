# Wiki Extensions plugin for Redmine
# Copyright (C) 2009  Haruyuki Iida
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

require_dependency 'projects_helper'

module RepositoryControlsProjectsHelperPatch
  def self.included(base) # :nodoc:
    base.send(:include, ProjectsHelperMethodsRepositoryControls)

    base.class_eval do
      unloadable # Send unloadable so it will not be unloaded in development

      alias_method_chain :project_settings_tabs, :repository_controls
    end

  end
end

module ProjectsHelperMethodsRepositoryControls
  def project_settings_tabs_with_repository_controls
    tabs = project_settings_tabs_without_repository_controls
    action = {:name => 'repository_controls', :controller => 'repository_controls', :action => :list, :partial => 'repository_controls/list', :label => :repository_controls}

    tabs << action if User.current.allowed_to?(action, @project)

    tabs
  end
end

ProjectsHelper.send(:include, RepositoryControlsProjectsHelperPatch)
