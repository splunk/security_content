require(['jquery','underscore','splunkjs/mvc', 'bootstrap.tab', 'splunkjs/mvc/simplexml/ready!'],
		function($, _, mvc){
	
	var tabsInitialzed = [];
	
	/**
	 * The below defines the tab handling logic.
	 */
	
	/**
	 * This hides the content associated with the tabs.
	 *
	 * The normal, auto-magical Bootstrap tab processing doesn't work for us since it requires a particular
	 * layout of HTML that we cannot use without converting the view entirely to simpleXML. So, we are
	 * going to handle it ourselves.
	 * @param {string} tabSetClass the 
	 */
	var hideTabTargets = function(tabSetClass) {

		var tabs = $('a[data-elements]');

		// If we are only applying this to a particular set of tabs, then limit the selector accordingly
		if (typeof tabSetClass !== 'undefined' && tabSetClass) {
			tabs = $('a.' + tabSetClass + '[data-elements]');
		}

		// Go through each toggle tab
		for (var c = 0; c < tabs.length; c++) {

			// Hide the targets associated with the tab
			var targets = $(tabs[c]).data("elements").split(",");

			for (var d = 0; d < targets.length; d++) {
				$('#' + targets[d], this.$el).hide();
			}
		}
	};
	
	/**
	 * Force a re-render of the panels with the given row ID.
	 *
	 * @param {string} row_id The ID of the row to force a rerender on
	 * @param {bool} force Force the tab to re-render even if it was already rendered once (defaults to true)
	 */
	var rerenderPanels = function(row_id, force){
		
		// Set a default argument for dont_rerender_until_needed
    	if( typeof force === 'undefined'){
    		force = true;
    	}
		
		// Don't do both if the panel was already rendered
		if( !force && _.contains(tabsInitialzed, row_id) ){
			return;
		}
		
		// Get the elements so that we can find the components to re-render
		var elements = $('#' + row_id + ' .dashboard-element');
		
		// Iterate the list and re-render the components so that they fill the screen
		for(var d = 0; d < elements.length; d++){
			
			// Determine if this is re-sizable
			if( $('#' + row_id + ' .ui-resizable').length > 0){
			
				var component = mvc.Components.get(elements[d].id);
				
				if(component){
					component.render();
				}
			}
		}
		
		// Remember that we initialized this tab
		tabsInitialzed.push(row_id);
	};
	
	/**
	 * Handles the selection of a partiular tab.
	 *
	 * @param {*} e 
	 */
	var selectTab = function (e) {
		// Update which tab is considered active
		$('#tabs > li.active').removeClass("active");
		$(e.target).closest("li").addClass("active");

		// clearTabControlTokens();
		setActiveTabToken();

		// Stop if the tabs have no elements
		if( $(e.target).data("elements") === undefined ){
			console.warn("Yikes, the clicked tab has no elements to hide!");
			return;
		}
		
		// Determine if the set of tabs has a restriction on the classes to manipulate
		var tabSet = null;

		if ($(e.target).data("tab-set") !== undefined) {
			tabSet = $(e.target).data("tab-set");
		}

		// Get the IDs that we should enable for this tab
		var toToggle = $(e.target).data("elements").split(",");
		
		// Hide the tab content by default
		hideTabTargets(tabSet);
		
		// Now show this tabs toggle elements
		for(var c = 0; c < toToggle.length; c++){
			
			// Show the items
			$('#' + toToggle[c], this.$el).show();
			
			// Re-render the panels under the item if necessary
			rerenderPanels(toToggle[c]);
		}
		
	};
    
    /**
     * The code below handles the tokens that trigger when searches are kicked off for a tab.
     */
    
	/**
	 * Get the tab token for a given tab name
	 * @param {string} tab_name The name of the tab
	 */
    var getTabTokenForTabName = function(tab_name){
    	return tab_name;
    };
    
    // Get all of the possible tab control tokens
    var getTabTokens = function(){
    	var tabTokens = [];
    	
    	var tabLinks = $('#tabs > li > a');
    	
    	for(var c = 0; c < tabLinks.length; c++){
    		tabTokens.push( getTabTokenForTabName( $(tabLinks[c]).data('token') ) );
    	}
    	
    	return tabTokens;
    };

	/**
	 * Clear all but the active tab control tokens
	 */
    var clearTabControlTokens = function(){
    	console.info("Clearing tab control tokens");
    	
    	//tabsInitialzed = [];
    	var tabTokens = getTabTokens();
    	var activeTabToken = getActiveTabToken();
    	var tokens = mvc.Components.getInstance("submitted");
    	
    	// Clear the tokens for all tabs except for the active one
    	for(var c = 0; c < tabTokens.length; c++){
    		
    		if( activeTabToken !== tabTokens[c] ){
    			tokens.set(tabTokens[c], undefined);
    		}
    	}
    };
    
	/**
	 * Get the tab control token for the active tab
	 */
    var getActiveTabToken = function(){
    	return $('#tabs > li.active > a').data('token');
    };
    
	/**
	 * Set the token for the active tab
	 */
    var setActiveTabToken = function(){
		var activeTabToken = getActiveTabToken();
		var tokens = mvc.Components.getInstance("submitted");
		
		if(activeTabToken){
			// Set each token if necessary
			activeTabToken.split(",").forEach(function(token){

				// If the token wasn't set, set it so that the searches can run
				if(!tokens.toJSON()[token] || tokens.toJSON()[token] == undefined){
					tokens.set(token, "");
				}
			});
		}
    };
	
	/**
	 * Handle the setting of the token for the clicked tab.
	 * @param {*} e 
	 */
    var setTokenForTab = function(e){
    	
		// Get the token for the tab
    	var tabToken = getTabTokenForTabName($(e.target).data('token'));
		
		// Set the token
		var tokens = mvc.Components.getInstance("submitted");
		tokens.set(tabToken, '');
		
		console.info("Set the token for the active tab (" + tabToken + ")");
    };
	
	/**
	 * Perform the initial setup for making the tabs work.
	 */
	var firstTimeTabSetup = function() { 
		$('a.toggle-tab').on('shown', setTokenForTab);
		
		// Wire up the function to show the appropriate tab
		$('a.toggle-tab').on('click shown', selectTab);
		
		// Show the first tab in each tab set
		$.each($('.nav-tabs'), function(index, value) {
			$('.toggle-tab', value).first().trigger('shown');
		});
		
		// Make the tabs into tabs
		$('#tabs', this.$el).tab();
		
		// Wire up the tab control tokenization
		var submit = mvc.Components.get("submit");
		
		if(submit){
			submit.on("submit", function() {
				clearTabControlTokens();
			});
		}
		
		// Set the token for the selected tab
		setActiveTabToken();
	};

	firstTimeTabSetup();
});
