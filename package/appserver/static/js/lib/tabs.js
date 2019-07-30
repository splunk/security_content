/* eslint import/no-dynamic-require: "off" */

require([
    'jquery',
    'underscore',
    'splunkjs/mvc',
    'bootstrap.tab',
    'splunkjs/mvc/simplexml/ready!',
], function(
    $,
    _,
    mvc
) {
    /**
     * The below defines the tab handling logic.
     */

    // The normal, auto-magical Bootstrap tab processing doesn't work for us since it requires a particular
    // layout of HTML that we cannot use without converting the view entirely to simpleXML. So, we are
    // going to handle it ourselves.
    const hideTabTargets = function() {
        const tabs = $('a[data-elements]');

        // Go through each toggle tab
        for (let c = 0; c < tabs.length; c += 1) {
            // Hide the targets associated with the tab
            const targets = $(tabs[c]).data("elements").split(",");

            for (let d = 0; d < targets.length; d += 1) {
                console.info(targets[d]);
                $(`#${ targets[d]}`, this.$el).hide();
            }
        }
    };

    const selectTab = function(e) {
        // Stop if the tabs have no elements
        if ($(e.target).data("elements") === undefined) {
            console.warn("Yikes, the clicked tab has no elements to hide!");
            return;
        }

        // Get the IDs that we should enable for this tab
        const toToggle = $(e.target).data("elements").split(",");

        // Hide the tab content by default
        hideTabTargets();

        // Now show this tabs toggle elements
        for (let c = 0; c < toToggle.length; c += 1) {
            $(`#${ toToggle[c]}`, this.$el).show();
        }
    };

    // Wire up the function to show the appropriate tab
    $('a[data-toggle="tab"]').on('shown', selectTab);

    // Show the first tab
    $('.toggle-tab').first().trigger('shown');

    // Make the tabs into tabs
    $('#tabs', this.$el).tab();

    /**
     * The code below handles the tokens that trigger when searches are kicked off for a tab.
     */

    // Get the tab token for a given tab name
    const getTabTokenForTabName = function(tabName) {
        return tabName; // "tab_" +
    };

    // Get all of the possible tab control tokens
    const getTabTokens = function() {
        const tabTokens = [];

        const tabLinks = $('#tabs > li > a');

        for (let c = 0; c < tabLinks.length; c += 1) {
            tabTokens.push(getTabTokenForTabName($(tabLinks[c]).data('token')));
        }

        return tabTokens;
    };

    // Get the tab control token for the active tab
    const getActiveTabToken = function() {
        return $('#tabs > li.active > a').data('token');
    };

    // Clear all but the active tab control tokens
    const clearTabControlTokens = function() {
        console.info("Clearing tab control tokens");

        const tabTokens = getTabTokens();
        const activeTabToken = getActiveTabToken();
        const tokens = mvc.Components.getInstance("submitted");

        // Clear the tokens for all tabs except for the active one
        for (let c = 0; c < tabTokens.length; c += 1) {
            if (activeTabToken !== tabTokens[c]) {
                tokens.set(tabTokens[c], undefined);
            }
        }
    };

    // Set the token for the active tab
    const setActiveTabToken = function() {
        const activeTabToken = getActiveTabToken();

        const tokens = mvc.Components.getInstance("submitted");

        tokens.set(activeTabToken, '');
    };

    const setTokenForTab = function(e) {
        // Get the token for the tab
        const tabToken = getTabTokenForTabName($(e.target).data('token'));

        // Set the token
        const tokens = mvc.Components.getInstance("submitted");
        tokens.set(tabToken, '');

        console.info(`Set the token for the active tab (${ tabToken })`);
    };

    $('a[data-toggle="tab"]').on('shown', setTokenForTab);

    // Wire up the tab control tokenization
    const submit = mvc.Components.get("submit");

    if(submit || submit !== undefined) {
            submit.on("submit", function() {
            clearTabControlTokens();
        });
    }

    // Set the token for the selected tab
    setActiveTabToken();
});