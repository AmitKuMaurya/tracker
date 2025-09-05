#ifndef LBS_LATLONG_H
#define LBS_LATLONG_H

#include "offline_data.h"

/**
 * Query Unwired Labs LocationAPI using cells from LBSData.
 * Tries unique cells in order and stops at first valid response.
 *
 * On success, allocates and populates a LocationData structure
 * with lat, lon, accuracy_m, address, and sets is_resolved flag.
 *
 * @param data In/out LBSData containing MCC, MNC and unique_cells
 * @return 0 on success, -1 on failure (no valid response from any cell)
 */
int lbs_query_unwired(LBSData *data);

#endif // LBS_LATLONG_H


