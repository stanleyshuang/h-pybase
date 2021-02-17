<template>
  <img alt="Vue logo" src="./assets/logo.png">
  <Ping msg="Welcome to Your Vue.js App"/>
</template>

<script>
import Ping from './components/Ping.vue'

export default {
  name: 'App',
  components: {
    Ping
  }
}
</script>

<style>
#app {
  font-family: Avenir, Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-align: center;
  color: #2c3e50;
  margin-top: 60px;
}
</style>
