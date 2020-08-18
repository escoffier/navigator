import React, { Component } from 'react';
import {
  ComposableMap,
  Geographies,
  Geography,
  Marker,
  ZoomableGroup,
} from 'react-simple-maps';

const geoUrl =
  'https://raw.githubusercontent.com/zcreativelabs/react-simple-maps/master/topojson-maps/world-110m.json';


const defaultMarkers = [
  { markerOffset: -15, name: '34.1.1.1', coordinates: [-68.1193, -16.4897] },
  { markerOffset: 25, name: '34.1.1.2', coordinates: [-47.8825, -15.7942] },
  { markerOffset: 25, name: '34.1.1.3', coordinates: [-70.6693, -33.4489] },
  { markerOffset: 25, name: '34.1.1.4', coordinates: [31.230398, 121.47370999999998] },
  { markerOffset: 25, name: '34.1.1.5', coordinates: [-74.0721, 4.711] },
  { markerOffset: -15, name: '34.1.1.6', coordinates: [-66.9036, 10.4806] },
  { markerOffset: -15, name: '34.1.1.7', coordinates: [-77.0428, -12.0464] },
];

class IpMap extends Component {
  render() {
    const { markers } = this.props;
    const data = markers || defaultMarkers;
    return (
        <ComposableMap
          projection="geoEqualEarth"
          projectionConfig={{
            width: 100,
            height: 200,
          }}
        >
          <ZoomableGroup zoom={1}>
          <Geographies geography={geoUrl}>
            {({ geographies }) =>
              geographies.map(geo => (
                  <Geography
                    key={geo.rsmKey}
                    geography={geo}
                    fill="#EAEAEC"
                    stroke="#D6D6DA"
                  />
                ))
            }
          </Geographies>
          {data.map(({ name, coordinates, markerOffset }) => (
            <Marker key={name} coordinates={coordinates}>
              <circle r={10} fill="#F00" stroke="#fff" strokeWidth={2} />
              <text
                textAnchor="middle"
                y={markerOffset}
                style={{ fontFamily: 'system-ui', fill: '#5D5A6D' }}
              >
                {name}
              </text>
            </Marker>
          ))}
          </ZoomableGroup>
        </ComposableMap>
      );
  }
}

export default IpMap;
