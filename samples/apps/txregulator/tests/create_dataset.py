# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import random
from time import strftime, gmtime
import csv

data_file = "sample_data.csv"

HEADER = ["origin", "destination", "amount", "type", "src_country", "dst_country", "display_country"]

KNOWN_OTHER_COUNTRIES = ["GB", "FR", "GR", "AU", "BR", "ZA", "JP", "IN"]
TYPES = ["PAYMENT", "TRANSFER", "CASH_OUT", "DEBIT", "CREDIT"]
rows = 100000
max_amount_moved = 1000000

PROBABILITY_OF_PICKING_US_TX = 0.8


def random_country_with_bias():
    return (
        "US"
        if random.random() < PROBABILITY_OF_PICKING_US_TX
        else random.choice(KNOWN_OTHER_COUNTRIES)
    )


with open(data_file, "a") as df:
    writer = csv.writer(df)
    writer.writerow(HEADER)
    for i in range(rows):
        src_country = random_country_with_bias()
        dst_country = random_country_with_bias()

        if src_country == dst_country == "US":
            country_to_display = "US"
        else:
            country_to_display = src_country if src_country != "US" else dst_country

        writer.writerow(
            [
                "C" + str(random.randint(1000, 9000)),
                "M" + str(random.randint(1000, 9000)),
                int(random.uniform(1, max_amount_moved)),
                random.choice(TYPES),
                src_country,
                dst_country,
                country_to_display,
            ]
        )
