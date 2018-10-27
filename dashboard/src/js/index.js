import '@babel/polyfill';

import React from 'react';
import ReactDOM from 'react-dom';

// init datepicker
import 'react-dates/initialize';
import 'react-dates/lib/css/_datepicker.css';

import App from './App';

ReactDOM.render(<App />, document.getElementById('app'))