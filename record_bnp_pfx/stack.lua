--
-- 
--
local table = require "table"
local Stack = {}

function Stack:new()
    local temp={}
    setmetatable(temp,self)
    self.__index=self
    self.stack_table = {}
    return temp
end

function Stack:push(element)
    local size = self:size()
    self.stack_table[size + 1] = element
end

function Stack:pop()
    local size = self:size()
    if self:is_empty() then
        printError("Error: Stack is empty!")
        return
    end
    return table.remove(self.stack_table,size)
end

function Stack:top()
    local size = self:size()
    if self:is_empty() then
        printError("Error: Stack is empty!")
        return
    end
    return self.stack_table[size]
end

function Stack:is_empty()
    local size = self:size()
    if size == 0 then
        return true
    end
    return false
end

function Stack:size()
    return #(self.stack_table) or 0
end

function Stack:clear()
    -- body
    self.stack_table = nil
    self.stack_table = {}
end

function Stack:printElement()
    local size = self:size()

    if self:is_empty() then
        -- printError("Error: Stack is empty!")
        return
    end

    local str = "{"..self.stack_table[size]
    size = size - 1
    while size > 0 do
        str = str..", "..self.stack_table[size]
        size = size - 1
    end
    str = str.."}"
    print(str)
end


return Stack