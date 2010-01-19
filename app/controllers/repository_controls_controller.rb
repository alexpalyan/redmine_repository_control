class RepositoryControlsController < ApplicationController

    unloadable
    layout 'base'

    before_filter :find_control, :except => [ :new, :browse ]
    before_filter :find_project, :only => :new
    before_filter :find_repository, :only => :browse
    #before_filter :authorize

    def new
        @control = RepositoryControl.new(params[:repository_control])

        if request.post?
            params[:repository_control][:path].each do |path|
                @control = RepositoryControl.new(params[:repository_control])
                @control.project_id = @project.id
                @control.path = path.to_s

                if @control.save
                    flash[:notice] = l(:notice_successful_create)
                end
            end

            redirect_to :controller => 'projects', :action => 'settings', :tab => 'repository_controls', :id => @project
        else
            @repository = @project.repository 
            @entries = @repository.entries('', '')
        end
    end

    def edit
        @project = Project.find(@control.project_id)

        if request.post?
            @control.update_attributes(params[:repository_control])
            flash[:notice] = l(:notice_successful_update)
            redirect_to :controller => 'projects', :action => 'settings', :tab => 'repository_controls', :id => @control.project_id
        else
            @repository = @project.repository 
            @entries = @repository.entries('', '')
        end
    end

    def browse
        @entries = @repository.entries(@path, @rev)
        if request.xhr?
            @entries ? render(:partial => 'dir_list_content') : render(:nothing => true)
        else
            show_error_not_found and return unless @entries
            @properties = @repository.properties(@path, @rev)
            render :action => 'browse'
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

    REV_PARAM_RE = %r{^[a-f0-9]*$}

    def find_repository
        @project = Project.find(params[:id])
        @repository = @project.repository
        render_404 and return false unless @repository
        @path = params[:path].join('/') unless params[:path].nil?
        @path ||= ''
        @rev = params[:rev]
        @rev_to = params[:rev_to]
        raise InvalidRevisionParam unless @rev.to_s.match(REV_PARAM_RE) && @rev.to_s.match(REV_PARAM_RE)
    rescue ActiveRecord::RecordNotFound
        render_404
    rescue InvalidRevisionParam
        show_error_not_found
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
