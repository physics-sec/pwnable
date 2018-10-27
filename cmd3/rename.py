def rename(string):
    matches = re.findall(r'[a-zA-Z]+', string)
    uniques = []
    for match in matches:
        if match not in uniques:
            uniques.append(match)
    for i in range(len(uniques)):
        string = re.sub(uniques[i], '_'*(2+i), string)
    print(string)
