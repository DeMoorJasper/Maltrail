import React from 'react';

import { defaultTableRowRenderer as DefaultTableRowRenderer, Column, Table, AutoSizer, SortDirection } from 'react-virtualized';
import { SEVERITY_ENUM } from '../enums';

const COLUMN_KEYS = [
  'sensor_name',
  'info',
  'trail_type',
  'severity',
  'src_ip',
  'dst_ip'
];

function rowRendererFactory(setSelectedTrail, trails) {
  return (props) => {
    return <DefaultTableRowRenderer {...props} onRowClick={({rowData}) => {
      let key = `${rowData.trail_type}-${rowData.src_ip}-${rowData.dst_ip}-${rowData.info}`;
      setSelectedTrail(trails[key]);
    }} />
  }
}

export default class Trails extends React.Component {
  constructor(props) {
    super(props);

    let list = Array.from(Object.values(this.props.trails));
    let sortBy = 'index';
    let sortDirection = SortDirection.ASC;
    let sortedList = this._sortList(list, {sortBy, sortDirection});

    this.state = {
      sortBy: sortBy,
      sortDirection: sortDirection,
      sortedList: sortedList
    }

    this.rowGetter = this.rowGetter.bind(this);
    this._sort = this._sort.bind(this);
    this._sortList = this._sortList.bind(this);
  }

  componentDidUpdate(prevProps) {
    if (prevProps.trails !== this.props.trails) {
      this._sort({
        sortBy: this.state.sortBy, 
        sortDirection: this.state.sortDirection
      });
    }
  }

  rowGetter({ index }) {
    let list = this.state.sortedList;
    let item = {}
    for (let key of COLUMN_KEYS) {
      item[key] = list[index][key];
    };
    item.severity = SEVERITY_ENUM[item.severity];
    return item;
  }

  _sort({sortBy, sortDirection}) {
    const sortedList = this._sortList({sortBy, sortDirection});

    this.setState({sortBy, sortDirection, sortedList});
  }

  _sortList({sortBy, sortDirection}) {
    let list = Array.from(Object.values(this.props.trails));

    let sortedList = list;
    
    if (sortBy !== 'index') {
      sortedList = sortedList.sort((a, b) => {
        if (typeof a[sortBy] === 'number') {
          return a[sortBy] - b[sortBy];
        }

        if (a[sortBy] < b[sortBy])
          return -1
        if (a[sortBy] > b[sortBy])
          return 1
        return 0
      });
    }

    if (sortDirection === SortDirection.DESC) {
      sortedList = sortedList.reverse();
    }

    return sortedList;
  }

  render() {
    let {
      sortBy,
      sortDirection
    } = this.state;
    
    return <div className="trails-table">
      <AutoSizer>
        {({ height, width }) => (
          <Table
            width={width}
            height={height}
            headerHeight={50}
            rowHeight={30}
            rowCount={this.state.sortedList.length}
            rowGetter={this.rowGetter.bind(this)}
            sort={this._sort}
            sortBy={sortBy}
            sortDirection={sortDirection}
            rowRenderer={rowRendererFactory(this.props.setSelectedTrail, this.props.trails)}
          >
            <Column
              label='Sensor'
              dataKey='sensor_name'
              width={500}
            />
            <Column
              width={500}
              label='Info'
              dataKey='info'
            />
            <Column
              width={250}
              label='Type'
              dataKey='trail_type'
            />
            <Column
              width={250}
              label='Severity'
              dataKey='severity'
            />
            <Column
              width={250}
              label='Source'
              dataKey='src_ip'
            />
            <Column
              width={250}
              label='Destination'
              dataKey='dst_ip'
            />
          </Table>
        )}
      </AutoSizer>
    </div>;
  }
}