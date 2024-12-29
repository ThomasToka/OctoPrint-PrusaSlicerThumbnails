/*
 * View model for OctoPrint-PrusaSlicerThumbnails
 *
 * Author: jneilliii
 * License: AGPLv3
 */
$(function() {
    function E3S1PROFORKBYTTThumbnailsViewModel(parameters) {
        var self = this;

		self.settingsViewModel = parameters[0];
		self.filesViewModel = parameters[1];
		self.printerStateViewModel = parameters[2];

		self.thumbnail_url = ko.observable('/static/img/tentacle-20x20.png');
		self.thumbnail_title = ko.observable('');
		self.inline_thumbnail = ko.observable();
		self.file_details = ko.observable();
		self.crawling_files = ko.observable(false);
		self.crawl_results = ko.observableArray([]);
		self.api_key = ko.observable("");
		self.filesViewModel.e3s1proforkbyttthumbnails_open_thumbnail = function(data) {
			if(data.thumbnail_src === "e3s1proforkbyttthumbnails"){
				var thumbnail_title = data.name.replace(/\.(?:gco(?:de)?|tft)$/,'');
				self.thumbnail_url(data.thumbnail);
				self.thumbnail_title(thumbnail_title);
				self.file_details(data);
				$('div#e3s1proforkbytt_thumbnail_viewer').modal("show");
			}
		};


		self.DEFAULT_THUMBNAIL_SCALE = "100%";
		self.filesViewModel.thumbnailScaleValue = ko.observable(self.DEFAULT_THUMBNAIL_SCALE);

		self.DEFAULT_THUMBNAIL_ALIGN = "left";
		self.filesViewModel.thumbnailAlignValue = ko.observable(self.DEFAULT_THUMBNAIL_ALIGN);

        self.DEFAULT_THUMBNAIL_POSITION = false;
		self.filesViewModel.thumbnailPositionLeft = ko.observable(self.DEFAULT_THUMBNAIL_POSITION);

		self.getThumbnailUrl = function() {
			// Check if the thumbnail URL contains ".png?" and replace it with ".jpg?"
			var url = self.thumbnail_url();
			if (url.toLowerCase().includes(".png?")) {
				return url.replace(/\.png\?/i, ".jpg?");
			} else {
				// If it doesn't contain ".png?", return it as is
				return url;
			}
		};

		self.crawl_files = function(){
			self.crawling_files(true);
			self.crawl_results([]);
			$.ajax({
				url: API_BASEURL + "plugin/e3s1proforkbyttthumbnails",
				type: "POST",
				dataType: "json",
				data: JSON.stringify({
					command: "crawl_files"
				}),
				contentType: "application/json; charset=UTF-8"
			}).done(function(data){
				for (key in data) {
					if(data[key].length){
						self.crawl_results.push({name: ko.observable(key), files: ko.observableArray(data[key])});
					}
				}
				if(self.crawl_results().length === 0){
					self.crawl_results.push({name: ko.observable('No convertible files found'), files: ko.observableArray([])});
				}
				self.filesViewModel.requestData({force: true});
				self.crawling_files(false);
			}).fail(function(data){
				self.crawling_files(false);
			});
		};

		self.onBeforeBinding = function() {
		    // inject filelist thumbnail into template

      let regex = /<div class="btn-group action-buttons">([\s\S]*)<.div>/mi;
			let template = '<div class="btn btn-mini" data-bind="click: function() { if ($root.loginState.isUser()) { $root.e3s1proforkbyttthumbnails_open_thumbnail($data) } else { return; } }, visible: ($data.thumbnail_src == \'e3s1proforkbyttthumbnails\' && $root.settingsViewModel.settings.plugins.e3s1proforkbyttthumbnails.inline_thumbnail() == false)" title="Show Thumbnail" style="display: none;"><i class="fa fa-image"></i></div>';

			let inline_thumbnail_template = '<div class="inline_e3s1proforkbytt_thumbnail" ' +
			                                'data-bind="if: ($data.thumbnail_src == \'e3s1proforkbyttthumbnails\' && $root.settingsViewModel.settings.plugins.e3s1proforkbyttthumbnails.inline_thumbnail() == true), style: {\'text-align\': $root.thumbnailAlignValue, \'width\': ($root.thumbnailPositionLeft()) ? $root.thumbnailScaleValue() : \'100%\'}, css: {\'row-fluid\': !$root.thumbnailPositionLeft(), \'pull-left\': $root.thumbnailPositionLeft()}">' +
			                                '<img data-bind="attr: {src: $data.thumbnail}, ' +
			                                'visible: ($data.thumbnail_src == \'e3s1proforkbyttthumbnails\' && $root.settingsViewModel.settings.plugins.e3s1proforkbyttthumbnails.inline_thumbnail() == true), ' +
			                                'click: function() { if ($root.loginState.isUser() && !($(\'html\').attr(\'id\') === \'touch\')) { $root.e3s1proforkbyttthumbnails_open_thumbnail($data) } else { return; } },' +
                                            'style: {\'width\': (!$root.thumbnailPositionLeft()) ? $root.thumbnailScaleValue() : \'100%\' }" ' +
			                                'style="display: none;"/></div>';


			$("#files_template_machinecode").text(function () {
				var return_value = inline_thumbnail_template + $(this).text();
				return_value = return_value.replace(regex, '<div class="btn-group action-buttons">$1	' + template + '></div>');
				return return_value;
			});

			// assign initial scaling
			if (self.settingsViewModel.settings.plugins.e3s1proforkbyttthumbnails.scale_inline_thumbnail()==true){
				self.filesViewModel.thumbnailScaleValue(self.settingsViewModel.settings.plugins.e3s1proforkbyttthumbnails.inline_thumbnail_scale_value() + "%");
			}

			// assign initial alignment
			if (self.settingsViewModel.settings.plugins.e3s1proforkbyttthumbnails.align_inline_thumbnail()==true){
				self.filesViewModel.thumbnailAlignValue(self.settingsViewModel.settings.plugins.e3s1proforkbyttthumbnails.inline_thumbnail_align_value());
			}

			// assign initial filelist height
            if(self.settingsViewModel.settings.plugins.e3s1proforkbyttthumbnails.resize_filelist()) {
                $('#files > div > div.gcode_files > div.scroll-wrapper').css({'height': self.settingsViewModel.settings.plugins.e3s1proforkbyttthumbnails.filelist_height() + 'px'});
            }

            // assign initial position
            if(self.settingsViewModel.settings.plugins.e3s1proforkbyttthumbnails.inline_thumbnail_position_left()==true) {
                self.filesViewModel.thumbnailPositionLeft(true);
            }

			// observe scaling changes
			self.settingsViewModel.settings.plugins.e3s1proforkbyttthumbnails.scale_inline_thumbnail.subscribe(function(newValue){
				if (newValue == false){
					self.filesViewModel.thumbnailScaleValue(self.DEFAULT_THUMBNAIL_SCALE);
				} else {
					self.filesViewModel.thumbnailScaleValue(self.settingsViewModel.settings.plugins.e3s1proforkbyttthumbnails.inline_thumbnail_scale_value() + "%");
				}
			});
			self.settingsViewModel.settings.plugins.e3s1proforkbyttthumbnails.inline_thumbnail_scale_value.subscribe(function(newValue){
				self.filesViewModel.thumbnailScaleValue(newValue + "%");
			});
			self.settingsViewModel.settings.plugins.e3s1proforkbyttthumbnails.state_panel_thumbnail_scale_value.subscribe(function(newValue){
				$('#e3s1proforkbytt_state_thumbnail').attr({'width': self.settingsViewModel.settings.plugins.e3s1proforkbyttthumbnails.state_panel_thumbnail_scale_value() + '%'});
                if(self.settingsViewModel.settings.plugins.e3s1proforkbyttthumbnails.state_panel_thumbnail_scale_value() !== 100) {
                    $('#e3s1proforkbytt_state_thumbnail').addClass('pull-left').next('hr').remove();
                }
			});

			// observe alignment changes
			self.settingsViewModel.settings.plugins.e3s1proforkbyttthumbnails.align_inline_thumbnail.subscribe(function(newValue){
				if (newValue == false){
					self.filesViewModel.thumbnailAlignValue(self.DEFAULT_THUMBNAIL_SCALE);
				} else {
					self.filesViewModel.thumbnailAlignValue(self.settingsViewModel.settings.plugins.e3s1proforkbyttthumbnails.inline_thumbnail_align_value());
				}
			});
			self.settingsViewModel.settings.plugins.e3s1proforkbyttthumbnails.inline_thumbnail_align_value.subscribe(function(newValue){
				self.filesViewModel.thumbnailAlignValue(newValue);
			});

			// observe position changes
            self.settingsViewModel.settings.plugins.e3s1proforkbyttthumbnails.inline_thumbnail_position_left.subscribe(function(newValue){
				self.filesViewModel.thumbnailPositionLeft(newValue);
			});

			// observe file list height changes
			self.settingsViewModel.settings.plugins.e3s1proforkbyttthumbnails.filelist_height.subscribe(function(newValue){
				if(self.settingsViewModel.settings.plugins.e3s1proforkbyttthumbnails.resize_filelist()) {
                    $('#files > div > div.gcode_files > div.scroll-wrapper').css({'height': self.settingsViewModel.settings.plugins.e3s1proforkbyttthumbnails.filelist_height() + 'px'});
                }
			});

			self.printerStateViewModel.dateString.subscribe(function(data){
				if(data){
					OctoPrint.files.get('local',self.printerStateViewModel.filepath())
						.done(function(file_data){
							if(file_data){
								if(self.settingsViewModel.settings.plugins.e3s1proforkbyttthumbnails.state_panel_thumbnail() && file_data.thumbnail && file_data.thumbnail_src == 'e3s1proforkbyttthumbnails'){
									if($('#e3s1proforkbytt_state_thumbnail').length) {
										$('#e3s1proforkbytt_state_thumbnail').attr('src', file_data.thumbnail);
									} else {
									    $('#state > div > hr:first').after('<img id="e3s1proforkbytt_state_thumbnail" class="pull-left" src="'+file_data.thumbnail+'" width="' + self.settingsViewModel.settings.plugins.e3s1proforkbyttthumbnails.state_panel_thumbnail_scale_value() + '%"/>');
										var $stateThumbnail = $('#e3s1proforkbytt_state_thumbnail');
										var $existingHr = $stateThumbnail.next('hr');
										if (self.settingsViewModel.settings.plugins.e3s1proforkbyttthumbnails.state_panel_thumbnail_scale_value() == 100) {
											if ($existingHr.length === 0) {
												$stateThumbnail.removeClass('pull-left').after('<hr id="e3s1proforkbytt_state_hr">');
											}
										} else {
											$existingHr.remove();
											$stateThumbnail.addClass('pull-left');
										}
                                        if(self.settingsViewModel.settings.plugins.e3s1proforkbyttthumbnails.relocate_progress()) {
                                            $('#state > div > div.progress.progress-text-centered').css({'margin-bottom': 'inherit'}).insertBefore('#e3s1proforkbytt_state_thumbnail').after('<hr>');
                                        }
									}
								} else {
									$('#e3s1proforkbytt_state_thumbnail').remove();
									if(self.settingsViewModel.settings.plugins.e3s1proforkbyttthumbnails.state_panel_thumbnail_scale_value() == 100) {
										$('#e3s1proforkbytt_state_hr').remove();
									}									
								}
							}
						})
						.fail(function(file_data){
							if($('#e3s1proforkbytt_state_thumbnail').length) {
								$('#e3s1proforkbytt_state_thumbnail').remove();
							}
						});
				} else {
				    $('#e3s1proforkbytt_state_thumbnail').remove();
                }
			});
		};

	}

	OCTOPRINT_VIEWMODELS.push({
		construct: E3S1PROFORKBYTTThumbnailsViewModel,
		dependencies: ['settingsViewModel', 'filesViewModel', 'printerStateViewModel'],
		elements: ['div#e3s1proforkbytt_thumbnail_viewer', '#crawl_files', '#crawl_files_results']
	});
});
