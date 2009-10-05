class RepositoryControlsController < ApplicationController

    unloadable
    layout 'base'

    before_filter :find_control, :except => :new
    before_filter :find_project, :only => :new
    #before_filter :authorize

    def new
        @control = RepositoryControl.new(params[:repository_control])
        if request.post?
            @control.project_id = @project.id

            if @control.save
                flash[:notice] = l(:notice_successful_create)
            end
            redirect_to :controller => 'projects', :action => 'settings', :tab => 'repository_controls', :id => @project
        end
    end

    def edit
        if request.post?
            @control.update_attributes(params[:repository_control])
            flash[:notice] = l(:notice_successful_update)
            redirect_to :controller => 'projects', :action => 'settings', :tab => 'repository_controls', :id => @control.project_id
        end
    end

    def destroy
        @project = Project.find(@control.project_id)
        @control.destroy
        respond_to do |format|
            format.html { redirect_to :controller => 'projects', :action => 'settings', :tab => 'repository_controls', :id => @project }
            format.js { render(:update) {|page| page.replace_html "tab-content-repository_controls", :partial => 'repository_controls/list'} }
        end
    end

    private
    def find_project
        @project = Project.find(params[:id])
        rescue ActiveRecord::RecordNotFound
            render_404
    end

    def find_control
        @control = RepositoryControl.find(params[:id])
        rescue ActiveRecord::RecordNotFound
            render_404

        logger.debug "Found control #{params[:id]} belonging to project #{@control.project_id}" if logger && logger.debug?
    end

    def find_user
        @user = User.current
    end
end
