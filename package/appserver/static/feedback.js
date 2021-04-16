
 require([
   'underscore',
   'jquery',
   'splunkjs/mvc',
   'splunkjs/mvc/simplexml/ready!'
 ], function(_, $, mvc, TableView) {

   var defaultTokenSpace = mvc.Components.getInstance('default');

   // This will take every textarea that has a data-token attribute and will make the given token with the value of the textarea
   $('textarea[data-token]').each(function (textarea) {
     $(this).on('input', function(input) {
         var token_to_set = $(this).data('token');
        defaultTokenSpace.set(token_to_set, $(this).val());
     })
   })
 });

