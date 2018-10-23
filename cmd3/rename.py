def rename(string):
    matches = re.findall(r'[a-z]+', string)
    uniques = []
    for match in matches:
        if match not in uniques:
            uniques.append(match)
    name = {}
    for i in range(len(uniques)):
        newname = '_'*(2+i)
        name[uniques[i]] = newname
    for i in range(len(uniques)):
        string = re.sub(uniques[i], name[uniques[i]], string)
    print(string)
