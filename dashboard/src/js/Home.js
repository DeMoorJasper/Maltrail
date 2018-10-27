import React from 'react';

import Search from './components/Search';
import Statistics from './components/Statistics';
import Trails from './components/Trails';

export default class Home extends React.Component {
  render() {
    return <main>
      <Statistics />
      <Search />
      <Trails />
    </main>;
  }
}