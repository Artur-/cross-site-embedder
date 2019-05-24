# Cross Site Embedder
Adds the required cross origin headers needed when embedding Vaadin applications from other sites

Works as a servlet filter so it is enough to add it as a project dependency.
Configure the allowed origins (sites where the app is embedded) by adding a `src/main/resources/cors.properties` file containing
```
origins=https://site1.com, https://site2.com/somepage.html
```
