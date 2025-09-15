#ifndef LBS_LATLONG_H
#define LBS_LATLONG_H

#include "offline_data.h"

/**
 * Query Google Geolocation API using cell towers and WiFi access points from LBSData.
 * Sends all unique cell towers and WiFi MAC addresses in a single request.
 *
 * On success, allocates and populates a LocationData structure
 * with lat, lon, accuracy_m and sets is_resolved flag.
 *
 * @param data In/out LBSData containing MCC, MNC, unique_cells, and unique_wifis
 * @return 0 on success, -1 on failure (no valid response or API error)
 */
int lbs_query_google(LBSData *data);

#endif // LBS_LATLONG_H


