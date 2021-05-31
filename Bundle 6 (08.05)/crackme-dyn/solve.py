bigint_1 = 25239776756291


def domod(pin: int):
    result = bigint_1 % pin
    if result == 0:
        return True
    else:
        return False


def main():
    for i in range(1000000):
        pin = "{0:06d}".format(i)
        if pin == "000000" or pin == "000001":
            continue
        print("Trying pin: ", pin)
        req_try = domod(int(pin))
        if req_try:
            print("Correct pin: " + pin)
            break
        else:
            continue


if __name__ == "__main__":
    main()
