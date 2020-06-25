require([
    'underscore',
    'jquery',
    'splunkjs/mvc',
    'splunkjs/mvc/searchmanager',
    'splunkjs/mvc/searchbarview',
    'splunkjs/mvc/tableview',
    'splunk.util',
    '../app/DA-ESS-ContentUpdate/js/lib/showdown.min',
    '../app/DA-ESS-ContentUpdate/js/lib/jquery-ui/jquery-ui',
    'css!../app/DA-ESS-ContentUpdate/js/lib/jquery-ui/jquery-ui.css',
    'css!../app/DA-ESS-ContentUpdate/analytic_story_details.css',
    'splunkjs/mvc/simplexml/ready!'
], function(_, $, mvc, SearchManager, SearchBarView, TableView, splunkUtil, showdown) {

    let tokenModel = mvc.Components.get("default");
    let renderedComponents = [];

    let templ = `
                 <div class="as_title_attr_bar">
                    <div class="as_title_attr">
                        <strong>Category: </strong><span id="as_label_category"></span>
                    </div>
                    <div class="as_title_attr">
                        <strong>Version: </strong><span id="as_label_version"></span>
                    </div>
                    <div class="as_title_attr">
                        <strong>Created: </strong><span id="as_label_created"></span>
                    </div>
                    <div class="as_title_attr">
                        <strong>Modified: </strong><span id="as_label_modified"></span>
                    </div>
                </div>
                <div class="headline_story">
                    <div class="heading-story">
                        <h1 id="story_heading"></h1>
                    </div>
                    <div class="run_story_btn">
                        <button class="btn btn-primary run-story">Run Analytics</button>
                    </div>
                </div>
                <div class="as_story_details">
                    <div class="as_story_details_right_col">
                        <div class="as_story_detail_right_attr_label">
                            <strong>Description: </strong>
                        </div>
                        <div class="as_story_detail_right_attr_label">
                            <span id="description"></span>
                        </div>
                        <div class="as_story_detail_right_attr_label">
                            <strong>Narrative: </strong>
                        </div>
                        <div class="as_story_detail_right_attr_label narrative_value">
                            <span id="narrative"></span>
                        </div>
                    </div>
                    <div class="as_story_details_left_col">
                        <div class="as_left_attr">
                            <div class="as_story_detail_left_attr_label">
                                <strong>ATT&CK: </strong>
                            </div>
                            <div class="as_story_detail_left_attr" id="mitre_attack">
                            </div>
                        </div>
                        <div class="as_left_attr">
                            <div class="as_story_detail_left_attr_label">
                                <strong>Kill Chain Phases: </strong>
                            </div>
                            <div class="as_story_detail_left_attr kill_chain_phases" id="kill_chain_phases">
                            </div>
                        </div>
                        <div class="as_left_attr">
                            <div class="as_story_detail_left_attr_label">
                                <strong>CIS Controls: </strong>
                            </div>
                            <div class="as_story_detail_left_attr" id="cis_20">
                            </div>
                        </div>
                        <div class="as_left_attr">
                            <div class="as_story_detail_left_attr_label">
                                <strong>Data Model: </strong>
                            </div>
                            <div class="as_story_detail_left_attr" id="data_model">
                            </div>
                        </div>
                        <div class="as_left_attr">
                            <div class="as_story_detail_left_attr_label">
                                <strong>References: </strong>
                            </div>
                            <div class="as_story_detail_left_attr" id="references">
                            </div>
                        </div>
                    </div>
                 </div>
                 <div class="as_search_details">
                    <h2>
                        Analytic Story Searches
                    </h2>
                    <div id="accordion">
                        <h3>Detection</h3>
                        <div>
                            <div id="search_detection">
                            </div>
                        </div>
                        <h3>Investigative</h3>
                        <div>
                            <div id="search_investigative">
                            </div>
                        </div>
                        <h3>Support</h3>
                        <div>
                            <div id="search_support">
                            </div>
                        </div>
                    </div>
                 </div>
                `;

    $('#analytic_story_details').html(_.template(templ));

    if (tokenModel.get('analytic_story_name')) {
        fetchAnalyticStoryDetails(tokenModel.get('analytic_story_name'));
    }

    tokenModel.on("change:analytic_story_name", function(model, value, options) {
        fetchAnalyticStoryDetails(value);
    });

    function fetchAnalyticStoryDetails(asName) {
        let epoch = (new Date).getTime();
        let searchGetAnalyticStoryData = new SearchManager({
            id: epoch,
            earliest_time: "-1h@h",
            latest_time: "now",
            cache: false,
            search: "| rest /services/configs/conf-analytic_stories splunk_server=local count=0 | search title=\"" + asName + "\" | spath input=reference path={} output=ref | spath input=data_models path={} output=dm | table title, category, description, version, mappings, creation_date, modification_date, dm, narrative, ref"
        });

        $('.run-story').unbind('click');

        $('.run-story').on('click', function(evt) {
        	window.open('/en-US/app/Splunk_ASX/execute?form.mode=now&form.cron=*%2F15%20*%20*%20*%20*&form.earliest_time=-15m&form.latest_time=now&form.time.earliest=-24h%40h&form.time.latest=now&form.story=' + asName);
        });

        let asSearch = splunkjs.mvc.Components.getInstance(epoch);
        let asResults = asSearch.data("results", {
            count: 0
        });
        asResults.on("data", function() {
            let as_attributes = {};
            let fields = asResults.data().fields;
            let rows = asResults.data().rows;

            for (let i = 0; i < fields.length; i++) {
                as_attributes[fields[i]] = rows[0][i];
            }
            renderStoryAttributes(as_attributes);
        });

        var searchGetSearchesData = new SearchManager({
            id: "s" + epoch,
            earliest_time: "-1h@h",
            latest_time: "now",
            cache: false,
            search: "| rest /services/saved/searches splunk_server=local count=0 | spath input=action.escu.analytic_story path={} output=uc | search uc = \"" + asName + "\" | spath input=action.escu.data_models path={} output=dm | table action.escu.full_search_name, search, description, action.escu.search_type, action.escu.how_to_implement, action.escu.eli5, action.escu.version, action.escu.mappings, dm, tex, action.escu.asset_at_risk, action.escu.confidence, action.escu.known_false_positives, updated, action.escu.modification_date, action.escu.creation_date "

        });
        var searchesSearch = splunkjs.mvc.Components.getInstance("s" + epoch);
        var searchesResults = searchesSearch.data("results", {
            count: 0
        });


        searchesResults.on("data", function() {
            let asSearchAttr = [];
            var fields = searchesResults.data().fields;
            var rows = searchesResults.data().rows;

            for (let i = 0; i < rows.length; i++) {
                let searchObj = {};
                for (let j = 0; j < fields.length; j++) {
                    searchObj[fields[j]] = rows[i][j];
                }
                asSearchAttr.push(searchObj);
            }
            renderSearches(asSearchAttr);
        });
    }

    function renderStoryAttributes(asAttributes) {
        let converter = new showdown.Converter();
        let mappings = JSON.parse(asAttributes.mappings);
        $('#as_label_category').html(asAttributes.category);
        $('#as_label_version').html(asAttributes.version);
        $('#as_label_created').html(asAttributes.creation_date);
        $('#as_label_modified').html(asAttributes.modification_date);
        $('#story_heading').html(asAttributes.title);
        $('#attack').html(mappings.mitre_attack);
        $('#narrative').html(converter.makeHtml(asAttributes.narrative));
        $('#description').html(converter.makeHtml(asAttributes.description));
        $('#mitre_attack').html(getValueLabels(mappings.mitre_attack, 'attack_tag'));
        $('#data_model').html(getValueLabels(asAttributes.dm, 'data_model_tag'));
        $('#kill_chain_phases').html(getValueLabels(mappings.kill_chain_phases, 'kill_chain_tag'));
        $('#cis_20').html(getValueLabels(mappings.cis20));
        $('#references').html(getReferenceURLS(asAttributes.ref));
    }

    function getReferenceURLS(refs) {
        if (refs === null) {
            return " ";
        } else {
            let refsResult = ``;
            if (Array.isArray(refs)) {
                refs.map(ref => {
                    refsResult = refsResult + `<a href="${ ref }">${ ref }</a><br />`;
                });
            } else {
                refsResult = refsResult + `<a href="${ refs }">${ refs }</a><br />`
            }

            return refsResult;
        }
    }

    function renderSearches(asSearches) {
        clearSearchView();
        let i = 0;
        let converter = new showdown.Converter();
        asSearches.forEach(search => {
            i++;
            let epoch = (new Date).getTime();
            let searchID = `#search${ i }`;
            let resultID = `#result${ i }`;
            let searchSelector = `search${ i }`;
            let controlID = `as_search${ i }`
            let resultsControlID = `as_results_search${ i }`;
            let btnID = `btn_es_${i}`;

            let searchPanel = `
                            <h3>${ search['action.escu.full_search_name'] }</h3>
                            <div class="search_content" id="${searchSelector}-content">
                                <div class="search_left_panel">
                                    <button class="configure_in_es btn btn-primary" id="${ btnID }" data-search-type="${search['action.escu.search_type']}"  data-search-name="${ search['action.escu.full_search_name'] }">Configure</button>
                                    <div class="search_left_attr">
                                        <div class="search_left_attr_label">
                                            <strong>Description</strong>
                                        </div>
                                        <div class="search_left_attr_value">
                                            ${ converter.makeHtml(search['description']) }
                                        </div>
                                    </div>
                                    <div id="${searchSelector}-eli5">
                                    </div>
                                    <div class="search_left_attr">
                                        <div class="search_left_attr_label">
                                            <strong>Search</strong>
                                        </div>
                                        <div class="search_left_attr_value ${ controlID }">
                                        </div>
                                        <div class="search_left_attr_value ${ resultsControlID }">
                                        </div>
                                    </div>
                                    <div class="search_left_attr">
                                        <div class="search_left_attr_label">
                                            <strong>How to Implement</strong>
                                        </div>
                                        <div class="search_left_attr_value">
                                            ${ converter.makeHtml(search['action.escu.how_to_implement']) }
                                        </div>
                                    </div>
                                    <div class="search_left_attr">
                                        <div class="search_left_attr_label">
                                            <strong>Known False Positives</strong>
                                        </div>
                                        <div class="search_left_attr_value">
                                            ${ converter.makeHtml(search['action.escu.known_false_positives']) }
                                        </div>
                                    </div>
                                </div>
                                <div class="search_right_panel">
                                    <div class="search_right_attr data_model_srch_attr">
                                        <div class="search_right_attr_label">
                                            <strong>Data Models</strong>
                                        </div>
                                        <div class="search_right_attr_value">
                                            ${ getValueLabels(search['dm'], 'data_model_tag') }
                                        </div>
                                    </div>
                                </div>
                            </div>`;

            if (search['action.escu.search_type'] === "support") {
                //Process Support Search Accordion

                let mappings = JSON.parse(search['action.escu.mappings']);
                $('#search_support').append(searchPanel);

                // Adding extra params to support search
                let supportLeftAttr = `<div class="search_left_attr">
                    <div class="search_right_attr_label">
                        <strong>Explain It Like I'm 5</strong>
                    </div>
                    <div class="search_left_attr_value">
                        ${ converter.makeHtml(search['action.escu.eli5']) }
                    </div>
                </div>`;


                $(`#${searchSelector}-eli5`).append(supportLeftAttr);

            } else if (search['action.escu.search_type'] === "detection") {
                let mappings = JSON.parse(search['action.escu.mappings']);
                $('#search_detection').append(searchPanel);
                // Adding extra params to detection search
                let detectionAttrTop = `
                <div class="search_right_attr">
                    <div class="search_right_attr_label">
                        <strong>ATT&CK</strong>
                    </div>
                    <div class="search_right_attr_value">
                        ${ getValueLabels(mappings.mitre_attack, 'attack_tag') }
                    </div>
                </div>
                <div class="search_right_attr">
                    <div class="search_right_attr_label">
                      <strong>Kill Chain Phases</strong>
                    </div>
                    <div class="search_right_attr_value">
                        ${ getValueLabels(mappings.kill_chain_phases, 'kill_chain_tag') }
                    </div>
                </div>
                <div class="search_right_attr">
                    <div class="search_right_attr_label">
                        <strong>CIS Controls</strong>
                    </div>
                    <div class="search_right_attr_value">
                        ${ getValueLabels(mappings.cis20) }
                    </div>
                </div>
                `;

                let detectionAttrBottom = `
                <div class="search_right_attr">
                    <div class="search_right_attr_label">
                        <strong>Asset at Risk</strong>
                    </div>
                    <div class="search_right_attr_value">
                        ${ search['action.escu.asset_at_risk'] }
                    </div>
                </div>
                <div class="search_right_attr">
                    <div class="search_right_attr_label">
                        <strong>Confidence</strong>
                    </div>
                    <div class="search_right_attr_value">
                        ${ search['action.escu.confidence'] }
                    </div>
                </div>
                 <div class="search_right_attr">
                    <div class="search_right_attr_label">
                        <strong>Creation Date</strong>
                    </div>
                    <div class="search_right_attr_value">
                        ${ search['action.escu.creation_date'] }
                    </div>
                </div>
                 <div class="search_right_attr">
                    <div class="search_right_attr_label">
                        <strong>Modification Date</strong>
                    </div>
                    <div class="search_right_attr_value">
                        ${ search['action.escu.modification_date'] }
                    </div>
                </div>`;

                let detectionLeftAttr = `<div class="search_left_attr">
                        <div class="search_right_attr_label">
                            <strong>Explain It Like I'm 5</strong>
                        </div>
                        <div class="search_left_attr_value">
                            ${ converter.makeHtml(search['action.escu.eli5']) }
                        </div>
                    </div>`;
                $(detectionAttrTop).insertBefore($(`#${searchSelector}-content`).find('.data_model_srch_attr'));
                $(`#${searchSelector}-content`).find('.search_right_panel').append(detectionAttrBottom);
                $(`#${searchSelector}-eli5`).append(detectionLeftAttr);
            } else if (search['action.escu.search_type'] === "contextual") {
                //Process contextual Search Accordion

                let mappings = JSON.parse(search['action.escu.mappings']);
                $('#search_contextual').append(searchPanel);


                // Adding extra params to contextual search
                let contextualLeftAttr = `<div class="search_left_attr">
                    <div class="search_right_attr_label">
                        <strong>Explain It Like I'm 5</strong>
                    </div>
                    <div class="search_left_attr_value">
                        ${ converter.makeHtml(search['action.escu.eli5']) }
                    </div>
                </div>`;
                $(`#${searchSelector}-eli5`).append(contextualLeftAttr);

            } else if (search['action.escu.search_type'] === "investigative") {
                //Process Investigative Search Accordion
                let mappings = JSON.parse(search['action.escu.mappings']);
                $('#search_investigative').append(searchPanel);

                // Adding extra params to investigative search
                let investigativeLeftAttr = `<div class="search_left_attr">
                    <div class="search_right_attr_label">
                        <strong>Explain It Like I'm 5</strong>
                    </div>
                    <div class="search_left_attr_value">
                        ${ converter.makeHtml(search['action.escu.eli5']) }
                    </div>
                </div>`;


                $(`#${searchSelector}-eli5`).append(investigativeLeftAttr);
            }

            /*
            let updatedAttr = `
            <div class="search_right_attr">
                <div class="search_right_attr_label">
                    <strong>Last Updated</strong>
                </div>
                <div class="search_right_attr_value">
                    ${ search['updated'] }
                </div>
            </div>
            `;
            $(`#${searchSelector}-content`).find('.search_right_panel').append(updatedAttr);
            */

            $(`#${ btnID }`).on('click', (evt) => {
                console.log($(evt.target).data("searchType"));
                if ($(evt.target).data("searchType") === "detection") {
                    splunkUtil.redirect_to('app/SplunkEnterpriseSecuritySuite/correlation_search_edit', {
                        search: `${$(evt.target).data("searchName")}`
                    }, window.open(), true);
                } else {
                    splunkUtil.redirect_to(`manager/DA-ESS-ContentUpdate/saved/searches`, {
                        search: `${$(evt.target).data("searchName")}`
                    }, window.open(), true);
                }
            })

            let searchManagerID = search['action.escu.full_search_name'].split(' ').join('');

            let searchManager = new SearchManager({
                id: searchManagerID,
                earliest_time: "-24h@h",
                latest_time: "now",
                status_buckets: 300,
                required_field_list: "*",
                preview: true,
                cache: true,
                autostart: false, // Prevent the search from running automatically
                search: search['search'],
            });

            let searchBar = new SearchBarView({
                id: searchID,
                managerId: searchManagerID,
                timerange: true,
                el: $('.' + controlID),
                value: search['search'],
                timerange_preset: "Last 24 hours"
            }).render();

            let tableviewer = new TableView({
                id: resultsControlID,
                managerid: searchManagerID,
                pageSize: 5,
                el: $("." + resultsControlID)
            }).render();

            searchBar.on("change", function() {
                searchManager.settings.unset("search");

                // Update the search query
                searchManager.settings.set("search", searchBar.val());

                // Run the search (because autostart=false)
                searchManager.startSearch();
            });

            searchBar.timerange.on("change", function() {
                // Update the time range of the search
                searchManager.search.set(searchBar.timerange.val());

                // Run the search (because autostart=false)
                searchManager.startSearch();
            })


            renderedComponents.push(searchID, searchManagerID, resultsControlID);

        });

        $('#accordion').accordion({
            heightStyle: "content"
        });
        $('#search_support').accordion({
            heightStyle: "content"
        });
        $('#search_detection').accordion({
            heightStyle: "content"
        });
        $('#search_contextual').accordion({
            heightStyle: "content"
        });
        $('#search_investigative').accordion({
            heightStyle: "content"
        });
    }

    function clearSearchView() {
        if ($('#accordion').hasClass('ui-accordion')) {
            $('#accordion').accordion('destroy');
        }

        if ($('#search_support').hasClass('ui-accordion')) {
            $('#search_support').accordion('destroy');
            $('#search_support').empty();
        }

        if ($('#search_detection').hasClass('ui-accordion')) {
            $('#search_detection').accordion('destroy');
            $('#search_detection').empty();
        }

        if ($('#search_contextual').hasClass('ui-accordion')) {
            $('#search_contextual').accordion('destroy');
            $('#search_contextual').empty();
        }

        if ($('#search_investigative').hasClass('ui-accordion')) {
            $('#search_investigative').accordion('destroy');
            $('#search_investigative').empty();
        }

        $('.configure_in_es').unbind("click");

        let len = renderedComponents.length;
        while (len--) {
            let id = renderedComponents.pop();
            mvc.Components.getInstance(id).dispose();
        }
    }

    function getValueLabels(values, className) {
        let cls = "";
        if (className !== undefined || className) {
            cls = className;
        }
        let valueArray = [];
        if (values) {
            if (typeof values === "string") {
                valueArray.push(values)
            } else {
                valueArray = values;
            }
        }
        let htmlTmpl = "";
        valueArray.forEach(val => {
            htmlTmpl += `<div class="value_label ${ cls }">${ val }</div>&nbsp;`
        });

        return htmlTmpl;
    }
});
