require([
   'underscore',
   'jquery',
   'splunkjs/mvc',
   'splunkjs/mvc/searchmanager',
   '../app/DA-ESS-ContentUpdate/js/lib/tabs',
   'css!../app/DA-ESS-ContentUpdate/js/lib/tabs.css',
   'css!../app/DA-ESS-ContentUpdate/escu_summary.css',
   'splunkjs/mvc/simplexml/ready!'
 ], function(_, $, mvc, SearchManager) {
    $('.all_results').html(_.template('<%- _("Detection Results").t() %>'));
    $('.all_entities').html(_.template('<%- _("Entities").t() %>'));
    $('.individual_entities').html(_.template('<%- _("Individual Entities").t() %>'));
    $('.investigate').html(_.template('<%- _("Investigate Results").t() %>'));

    const tokenModel = mvc.Components.get('default');
    const submittedTokens = mvc.Components.get('submitted');

    
 });
