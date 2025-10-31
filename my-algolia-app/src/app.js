const { algoliasearch, instantsearch } = window;

const searchClient = algoliasearch('6QZOPSI8T0', '7ac97a5c7a3410ac929a22f66ca19246');

const search = instantsearch({
  indexName: 'algolia_movie_sample_dataset',
  searchClient,
  future: { preserveSharedStateOnUnmount: true },
  
});


search.addWidgets([
  instantsearch.widgets.searchBox({
    container: '#searchbox',
  }),
  instantsearch.widgets.hits({
    container: '#hits',
  }),
  instantsearch.widgets.configure({
    hitsPerPage: 8,
  }),
  instantsearch.widgets.pagination({
    container: '#pagination',
  }),
]);

search.start();

